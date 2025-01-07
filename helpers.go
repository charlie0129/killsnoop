//go:build linux

package main

import (
	"bytes"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

func cmdlineConv(in []byte) []string {
	var ret []string
	for _, a := range bytes.Split(in, []byte{0x0}) {
		if len(a) != 0 {
			ret = append(ret, string(a))
		}
	}
	return ret
}

func getMaxPid() int64 {
	s, err := os.ReadFile(path.Join(root, "proc/sys/kernel/pid_max"))
	if err != nil {
		return math.MaxInt32
	}
	i, err := strconv.ParseInt(strings.TrimSpace(string(s)), 10, 64)
	if err != nil || i < 0 {
		return math.MaxInt32
	}
	return int64(i)
}