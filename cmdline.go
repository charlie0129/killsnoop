package main

import (
	"log/slog"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Process struct {
	// /proc/pid/cmdline
	Cmdline []string
	// /proc/pid/comm
	Comm string
	PID  int64
	PPID int64
}

type ProcessCache struct {
	c  map[int64]*Process
	mu *sync.RWMutex
}

func NewProcessCache() *ProcessCache {
	c := &ProcessCache{
		c:  map[int64]*Process{},
		mu: &sync.RWMutex{},
	}

	go func() {
		for {
			cmdline := listProcesses(maxPid)
			c.mu.Lock()
			c.c = cmdline
			c.mu.Unlock()
			time.Sleep(time.Duration(listProcessInterval) * time.Second)
		}
	}()

	return c
}

func (c *ProcessCache) Insert(p *Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.c[p.PID] = p
}

// Lookup retturns nil if not found.
func (c *ProcessCache) Lookup(pid int64) *Process {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c[pid]
}

func listProcesses(maxpid int64) map[int64]*Process {
	ret := map[int64]*Process{}
	mu := &sync.Mutex{}

	stime := time.Now()
	defer func() {
		diff := time.Since(stime).Milliseconds()
		slog.Debug("listed process", "msElapsed", diff, "items", len(ret))
	}()

	getProcess := func(pid int64) {
		proc := getProcessFromProc(pid)
		if proc == nil {
			return
		}

		mu.Lock()
		ret[pid] = proc
		mu.Unlock()
	}

	pids := listPids(maxpid)

	// We want to do parallel listing to speed up.
	// So we split the pids into maxListProcessThreads groups, and spawn maxListProcessThreads goroutines to get them.
	var perGoroutinePids [][]int64
	for range maxListProcessThreads {
		perGoroutinePids = append(perGoroutinePids, []int64{})
	}

	for i, pid := range pids {
		whichGoroutine := i % maxListProcessThreads
		perGoroutinePids[whichGoroutine] = append(perGoroutinePids[whichGoroutine], pid)
	}

	// Let them go!
	wg := sync.WaitGroup{}
	wg.Add(len(perGoroutinePids))
	for _, gPids := range perGoroutinePids {
		go func() {
			defer wg.Done()
			for _, pid := range gPids {
				getProcess(pid)
			}
		}()
	}
	wg.Wait()

	return ret
}

func listPids(maxpid int64) []int64 {
	proc, err := os.ReadDir(path.Join(root, "proc"))
	if err != nil {
		return nil
	}

	var pids []int64

	for _, d := range proc {
		if !d.IsDir() {
			continue
		}

		isPid := true
		for _, i := range d.Name() {
			if i < '0' || i > '9' {
				isPid = false
				break
			}
		}
		if !isPid {
			continue
		}

		pid, err := strconv.ParseInt(d.Name(), 10, 32)
		if err != nil || pid <= 0 { // no pid 0 in proc
			continue
		}

		if pid > maxpid {
			continue
		}

		pids = append(pids, pid)
	}

	return pids
}

func getProcessFromProc(pid int64) *Process {
	cmdlineBytes, err := os.ReadFile(path.Join(root, "proc", strconv.FormatInt(pid, 10), "cmdline"))
	if err != nil || len(cmdlineBytes) == 0 {
		return nil
	}
	cmdline := cmdlineConv(cmdlineBytes)

	statBytes, err := os.ReadFile(path.Join(root, "proc", strconv.FormatInt(pid, 10), "stat"))
	if err != nil || len(statBytes) == 0 {
		return nil
	}

	stat := string(statBytes)
	binStart := strings.IndexRune(stat, '(') + 1
	binEnd := strings.IndexRune(stat[binStart:], ')')
	binary := stat[binStart : binStart+binEnd]

	// Move past the image name and start parsing the rest
	stat = stat[binStart+binEnd+4:]
	ppidStr := stat[:strings.IndexRune(stat, ' ')]
	ppid, err := strconv.ParseInt(ppidStr, 10, 64)
	if err != nil {
		return nil
	}

	return &Process{
		Cmdline: cmdline,
		Comm:    binary,
		PPID:    ppid,
		PID:     pid,
	}
}
