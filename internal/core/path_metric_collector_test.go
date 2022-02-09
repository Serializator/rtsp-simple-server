package core

import (
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"strings"
	"testing"
)

type dummyPathManager struct {
	res pathAPIPathsListRes
}

func (pm dummyPathManager) onAPIPathsList(_ pathAPIPathsListReq) pathAPIPathsListRes {
	return pm.res
}

func TestPathCollector_Collect(t *testing.T) {
	testCases := []struct{
		items    map[string]pathAPIPathsListItem
		expected string
	}{
		{
			items: map[string]pathAPIPathsListItem{
				"path1": { SourceReady: true },
				"path2": { SourceReady: true },
				"path3": { SourceReady: false },
			}, expected: fmt.Sprintf(`
# HELP paths %v
# TYPE paths gauge
paths{name="path1", state="ready"} 1
paths{name="path2", state="ready"} 1
paths{name="path3", state="notReady"} 1
`, pathPathsDescHelp),
		},
	}

	for _, testCase := range testCases {
		metrics := metrics{
			pathManager: dummyPathManager{
				res: pathAPIPathsListRes{
					data: &pathAPIPathsListData{
						Items: testCase.items,
					},
				},
			},
		}

		err := testutil.CollectAndCompare(newPathCollector(&metrics), strings.NewReader(testCase.expected))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPathCollector_CollectErr(t *testing.T) {
	metrics := metrics{
		pathManager: dummyPathManager{
			res: pathAPIPathsListRes{
				err: errors.New("hello, world"),
			},
		},
	}

	err := testutil.CollectAndCompare(newPathCollector(&metrics), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
}