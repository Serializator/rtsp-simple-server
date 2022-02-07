package rtmp

type message struct {
	timenow     uint32
	timedelta   uint32
	hastimeext  bool
	timeext     uint32
	msgsid      uint32
	msgtypeid   uint8
	msgdatalen  uint32
	msgdataleft uint32
	msghdrtype  uint8
	msgdata     []byte
	sendack     uint32

	malloc func(int) ([]byte, error)

	aggreadp   []byte
	aggfirsttm uint32
	aggidx     int
}

func msgReadChunk(r io.Reader) (*message, error) {
	buf := make([]byte, 1)
	_, err := r.Read(buf)
	if err != nil {
		return nil, err
	}

	header := buf[0]

	csid := uint32(header) & 0x3f
	switch csid {
	default:
	case 0:
		buf := make([]byte, 1)
		_, err := r.Read(buf)
		if err != nil {
			return nil, err
		}

		csid = uint32(buf[0]) + 64

	case 1:
		buf := make([]byte, 2)
		_, err := r.Read(buf)
		if err != nil {
			return nil, err
		}

		csid = uint32(pio.U16BE(buf)) + 64
	}

	msghdrtype := header >> 6

	switch msghdrtype {
	case 0:



	kjhgv

	newcs := false
	cs := c.readcsmap[csid]
	if cs == nil {
		cs = &message{}
		c.readcsmap[csid] = cs
		newcs = true
	}
	if len(c.readcsmap) > 16 {
		err = fmt.Errorf("TooManyCsid")
		return
	}

}
