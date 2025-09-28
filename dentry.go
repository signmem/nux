package nux

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"io"
	"strings"
	"strconv"
	"github.com/signmem/file"
)

type Dentry struct {
	NR_DENTRY	uint64
	NR_UNUSED	uint64
	AGE_LIMIT	uint64
	WANT_PAGES	uint64
	NR_NEGATIVE	uint64
	DUMMY		uint64
}

func (this *Dentry) String() string {
	return fmt.Sprintf("<nr_dentry:%d, nr_unused:%d, age_limit:%d, want_pages:%d, nr_negative:%d, dummy:%d>", this.NR_DENTRY, this.NR_UNUSED, this.AGE_LIMIT, this.WANT_PAGES, this.NR_NEGATIVE, this.DUMMY)
}


func DentryInfo() (*Dentry, error) {
	contents, err := ioutil.ReadFile( "/proc/sys/fs/dentry-state")
	if err != nil {
		return nil, err
	}

	dentryInfo := &Dentry{}

	reader := bufio.NewReader(bytes.NewBuffer(contents))

	for {
		line, err := file.ReadLine(reader)
		if err == io.EOF {
			err = nil
			break
		} else if err != nil {
			return nil, err
		}

		fields := strings.Fields(string(line))
		dentryInfo.NR_DENTRY, _		= strconv.ParseUint(fields[0], 10, 64)
		dentryInfo.NR_UNUSED, _		= strconv.ParseUint(fields[1], 10, 64)
		dentryInfo.AGE_LIMIT, _		= strconv.ParseUint(fields[2], 10, 64)
		dentryInfo.WANT_PAGES, _	= strconv.ParseUint(fields[3], 10, 64)
		dentryInfo.NR_NEGATIVE, _	= strconv.ParseUint(fields[4], 10, 64)
		dentryInfo.DUMMY, _		= strconv.ParseUint(fields[5], 10, 64)
	}
	return dentryInfo, nil
}
