package rtmp

import (
	"net"
	"testing"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"bytes"
	"fmt"
	"encoding/json"
	"math"
	"time"
	"net/url"
	"strings"

	"github.com/stretchr/testify/require"
	"github.com/notedit/rtmp/utils/bits/pio"
)

var (
	hsClientFullKey = []byte{
		'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
		'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ',
		'0', '0', '1',
		0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
		0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
		0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
	}
	hsServerFullKey = []byte{
		'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
		'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
		'S', 'e', 'r', 'v', 'e', 'r', ' ',
		'0', '0', '1',
		0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1,
		0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
		0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE,
	}
	hsClientPartialKey = hsClientFullKey[:30]
	hsServerPartialKey = hsServerFullKey[:36]
)

const (
	chunkHeader0Length = 16
	writeMaxChunkSize = 128
	msgtypeidCommandMsgAMF0   = 20
)

func splitPath(u *url.URL) (app, stream string) {
	nu := *u
	nu.ForceQuery = false

	pathsegs := strings.SplitN(nu.RequestURI(), "/", -1)
	if len(pathsegs) == 2 {
		app = pathsegs[1]
	}
	if len(pathsegs) == 3 {
		app = pathsegs[1]
		stream = pathsegs[2]
	}
	if len(pathsegs) > 3 {
		app = strings.Join(pathsegs[1:3], "/")
		stream = strings.Join(pathsegs[3:], "/")
	}
	return
}

func fillChunkHeader3(b []byte, csid uint32, timestamp uint32) (n int) {
	pio.WriteU8(b, &n, (byte(csid)&0x3f)|3<<6)
	if timestamp >= 0xffffff {
		pio.WriteU32BE(b, &n, timestamp)
	}
	return
}

func fillChunkHeader0MsgDataLen(b []byte, msgdatalen int) {
	pio.PutU24BE(b[4:], uint32(msgdatalen))
}

func fillChunkHeader0(b []byte, csid uint32, timestamp uint32, msgtypeid uint8, msgsid uint32, msgdatalen int) (n int) {
	pio.WriteU8(b, &n, byte(csid)&0x3f)

	if timestamp >= 0xffffff {
		pio.WriteU24BE(b, &n, 0xffffff)
	} else {
		pio.WriteU24BE(b, &n, timestamp)
	}

	pio.WriteU24BE(b, &n, uint32(msgdatalen))
	pio.WriteU8(b, &n, msgtypeid)

	pio.WriteU32LE(b, &n, msgsid)

	if timestamp >= 0xffffff {
		pio.WriteU32BE(b, &n, timestamp)
	}

	return
}

func hsMakeDigest(key []byte, src []byte, gap int) (dst []byte) {
	h := hmac.New(sha256.New, key)
	if gap <= 0 {
		h.Write(src)
	} else {
		h.Write(src[:gap])
		h.Write(src[gap+32:])
	}
	return h.Sum(nil)
}

func hsCalcDigestPos(p []byte, base int) (pos int) {
	for i := 0; i < 4; i++ {
		pos += int(p[base+i])
	}
	pos = (pos % 728) + base + 4
	return
}

func hsFindDigest(p []byte, key []byte, base int) int {
	gap := hsCalcDigestPos(p, base)
	digest := hsMakeDigest(key, p, gap)
	if bytes.Compare(p[gap:gap+32], digest) != 0 {
		return -1
	}
	return gap
}

func hsParse1(p []byte, peerkey []byte, key []byte) (ok bool, digest []byte) {
	var pos int
	if pos = hsFindDigest(p, peerkey, 772); pos == -1 {
		if pos = hsFindDigest(p, peerkey, 8); pos == -1 {
			return
		}
	}
	ok = true
	digest = hsMakeDigest(key, p[pos:pos+32], -1)
	return
}

func handshakeC2(key []byte) []byte {
	buf := make([]byte, 1536)
	rand.Read(buf)
	gap := len(buf) - 32
	digest := hsMakeDigest(key, buf, gap)
	copy(buf[gap:], digest)
	return buf
}

func handshakeC0C1() []byte {
	buf := make([]byte, 1537)
	buf[0] = 0x03
	copy(buf[1:5], []byte{0x00, 0x00, 0x00, 0x00})
	copy(buf[5:9], []byte{0x09, 0x00, 0x7c, 0x02})
	rand.Read(buf[1+8:])
	gap := hsCalcDigestPos(buf[1:], 8)
	digest := hsMakeDigest(hsClientPartialKey, buf[1:], gap)
	copy(buf[gap+1:], digest)
	return buf
}

func fillAMF0Number(b []byte, n *int, f float64) {
	pio.WriteU8(b, n, numbermarker)
	fillBEFloat64(b, n, f)
}

type AMFKv struct {
	K string
	V interface{}
}
type AMFMap []AMFKv

func (a AMFMap) Get(k string) *AMFKv {
	for i := range a {
		kv := &a[i]
		if kv.K == k {
			return kv
		}
	}
	return nil
}

func (a AMFMap) GetString(k string) (string, bool) {
	v, ok := a.GetV(k)
	if !ok {
		return "", false
	}
	s, typeok := v.(string)
	return s, typeok
}

func (a AMFMap) GetBool(k string) (bool, bool) {
	v, ok := a.GetV(k)
	if !ok {
		return false, false
	}
	b, typeok := v.(bool)
	return b, typeok
}

func (a AMFMap) GetFloat64(k string) (float64, bool) {
	v, ok := a.GetV(k)
	if !ok {
		return 0, false
	}
	f, typeok := v.(float64)
	return f, typeok
}

func (a AMFMap) GetV(k string) (interface{}, bool) {
	kv := a.Get(k)
	if kv == nil {
		return nil, false
	}
	return kv.V, true
}

func (a AMFMap) Del(dk string) AMFMap {
	nm := AMFMap{}
	for _, kv := range a {
		if kv.K != dk {
			nm = append(nm, kv)
		}
	}
	return nm
}

func (a AMFMap) Set(k string, v interface{}) AMFMap {
	kv := a.Get(k)
	if kv == nil {
		return append(a, AMFKv{k, v})
	}
	kv.V = v
	return a
}

func (a AMFMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("{")
	for i, kv := range a {
		if i != 0 {
			buf.WriteString(",")
		}
		key, err := json.Marshal(kv.K)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteString(":")
		val, err := json.Marshal(kv.V)
		if err != nil {
			return nil, err
		}
		buf.Write(val)
	}

	buf.WriteString("}")
	return buf.Bytes(), nil
}

const (
	numbermarker = iota
	booleanmarker
	stringmarker
	objectmarker
	movieclipmarker
	nullmarker
	undefinedmarker
	referencemarker
	ecmaarraymarker
	objectendmarker
	strictarraymarker
	datemarker
	longstringmarker
	unsupportedmarker
	recordsetmarker
	xmldocumentmarker
	typedobjectmarker
	avmplusobjectmarker
)

type AMFArray []interface{}
type AMFECMAArray AMFMap

func fillBEFloat64(b []byte, n *int, f float64) {
	pio.WriteU64BE(b, n, math.Float64bits(f))
}

func FillAMF0Val(b []byte, n *int, _val interface{}) {
	switch val := _val.(type) {
	case int8:
		fillAMF0Number(b, n, float64(val))
	case int16:
		fillAMF0Number(b, n, float64(val))
	case int32:
		fillAMF0Number(b, n, float64(val))
	case int64:
		fillAMF0Number(b, n, float64(val))
	case int:
		fillAMF0Number(b, n, float64(val))
	case uint8:
		fillAMF0Number(b, n, float64(val))
	case uint16:
		fillAMF0Number(b, n, float64(val))
	case uint32:
		fillAMF0Number(b, n, float64(val))
	case uint64:
		fillAMF0Number(b, n, float64(val))
	case uint:
		fillAMF0Number(b, n, float64(val))
	case float32:
		fillAMF0Number(b, n, float64(val))
	case float64:
		fillAMF0Number(b, n, float64(val))

	case string:
		u := len(val)
		if u < 65536 {
			pio.WriteU8(b, n, stringmarker)
			pio.WriteU16BE(b, n, uint16(u))
		} else {
			pio.WriteU8(b, n, longstringmarker)
			pio.WriteU32BE(b, n, uint32(u))
		}
		pio.WriteString(b, n, val)

	case AMFECMAArray:
		pio.WriteU8(b, n, ecmaarraymarker)
		pio.WriteU32BE(b, n, uint32(len(val)))
		for _, p := range val {
			pio.WriteString(b, n, p.K)
			FillAMF0Val(b, n, p.V)
		}
		pio.WriteU24BE(b, n, 0x000009)

	case AMFMap:
		pio.WriteU8(b, n, objectmarker)
		for _, p := range val {
			if len(p.K) > 0 {
				pio.WriteU16BE(b, n, uint16(len(p.K)))
				pio.WriteString(b, n, p.K)
				FillAMF0Val(b, n, p.V)
			}
		}
		pio.WriteU24BE(b, n, 0x000009)

	case AMFArray:
		pio.WriteU8(b, n, strictarraymarker)
		pio.WriteU32BE(b, n, uint32(len(val)))
		for _, v := range val {
			FillAMF0Val(b, n, v)
		}

	case time.Time:
		pio.WriteU8(b, n, datemarker)
		u := val.UnixNano()
		f := float64(u / 1000000)
		fillBEFloat64(b, n, f)
		pio.WriteU16BE(b, n, uint16(0))

	case bool:
		pio.WriteU8(b, n, booleanmarker)
		var u uint8
		if val {
			u = 1
		} else {
			u = 0
		}
		pio.WriteU8(b, n, u)

	case nil:
		pio.WriteU8(b, n, nullmarker)
	}

	return
}

func FillAMF0Vals(b []byte, vals []interface{}) (n int) {
	for _, v := range vals {
		if _b, ok := v.([]byte); ok {
			pio.WriteBytes(b, &n, _b)
		} else {
			FillAMF0Val(b, &n, v)
		}
	}
	return
}

func fillAMF0Vals(args []interface{}) []byte {
	b := make([]byte, FillAMF0Vals(nil, args))
	FillAMF0Vals(b, args)
	return b
}

func msg(csid uint32, msg message, fillheader func([]byte) int) []byte {
	if fillheader == nil {
		fillheader = func(b []byte) int { return 0 }
	}

	var ret bytes.Buffer

	buf := make([]byte, chunkHeader0Length)
	chdrlen := fillChunkHeader0(buf, csid, msg.timenow, msg.msgtypeid, msg.msgsid, 0)
	taghdrlen := fillheader(buf[chdrlen:])
	msg.msgdatalen = uint32(taghdrlen + len(msg.msgdata))
	msg.msgdataleft = msg.msgdatalen
	fillChunkHeader0MsgDataLen(buf, int(msg.msgdatalen))
	wb := buf[:chdrlen+taghdrlen]
	ret.Write(wb)

	chunkleft := writeMaxChunkSize - taghdrlen
	if chunkleft < 0 {
		panic(fmt.Sprintf("TagHdrTooLong(%d,%d)", writeMaxChunkSize, taghdrlen))
	}
	msg.msgdataleft -= uint32(taghdrlen)

	i := 0

	for msg.msgdataleft > 0 {
		if i > 0 {
			n := fillChunkHeader3(buf, csid, msg.timenow)
			ret.Write(buf[:n])
		}

		n := int(msg.msgdataleft)
		if n > chunkleft {
			n = chunkleft
		}

		start := int(msg.msgdatalen-msg.msgdataleft) - taghdrlen
		ret.Write(msg.msgdata[start : start+n])
		chunkleft -= n
		msg.msgdataleft -= uint32(n)

		if chunkleft == 0 {
			chunkleft = writeMaxChunkSize
		}

		i++
	}

	return ret.Bytes()
}

func cmd(csid, msgsid uint32, args ...interface{}) []byte {
	return msg(csid, message{
		msgtypeid: msgtypeidCommandMsgAMF0,
		msgsid:    msgsid,
		msgdata:   fillAMF0Vals(args),
	}, nil)
}

func getTcURL(u string) string {
	ur, err := url.Parse(u)
	if err != nil {
		panic(err)
	}
	app, _ := splitPath(ur)
	nu := *ur
	nu.RawQuery = ""
	nu.Path = "/"
	return nu.String() + app
}

func cmdConnect(u string, path string) []byte {
	return cmd(3, 0, "connect", 1,
		AMFMap{
			{K: "app", V: path},
			{K: "flashVer", V: "LNX 9,0,124,2"},
			{K: "tcUrl", V: getTcURL(u)},
			{K: "fpad", V: false},
			{K: "capabilities", V: 15},
			{K: "audioCodecs", V: 4071},
			{K: "videoCodecs", V: 252},
			{K: "videoFunction", V: 1},
		},
	)
}

func TestReadMetadata(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9121")
	require.NoError(t, err)
	defer ln.Close()

	temp := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		require.NoError(t, err)
		defer conn.Close()

		rconn := NewServerConn(conn)
		err = rconn.ServerHandshake()
		require.NoError(t, err)
		fmt.Println("asdasd")
		close(temp)
	}()

	conn, err := net.Dial("tcp", "127.0.0.1:9121")
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(handshakeC0C1())
	require.NoError(t, err)

	s0s1s2 := make([]byte, 1536*2 + 1)
	_, err = conn.Read(s0s1s2)
	require.NoError(t, err)

	ok, digest2 := hsParse1(s0s1s2[1:1537], hsServerPartialKey, hsClientFullKey)
	require.Equal(t, true, ok)
	_, err = conn.Write(handshakeC2(digest2))
	require.NoError(t, err)

	_, err = conn.Write(cmdConnect("rtmp://127.0.0.1:9121/stream", "/stream"))
	require.NoError(t, err)

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	fmt.Println(n)
	<-temp
}
