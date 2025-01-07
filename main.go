//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var (
	listProcessInterval   = 3
	logLevelStr           = "info"
	maxParentDepth        = 8
	maxListProcessThreads = runtime.GOMAXPROCS(0)
	ignoreSourceComm      = stringArray{}
	root                  = "/"

	logLevel slog.Level
	maxPid   = int64(math.MaxInt32)
)

func init() {
	maxPid = getMaxPid()
	// Cap max listing goroutines. Too many of them will not do any benefits.
	if maxListProcessThreads > 8 {
		maxListProcessThreads = 8
	}
}

func main() {
	flag.IntVar(&listProcessInterval, "listProcessInterval", listProcessInterval, "List existing process interval (for finding terminated processes)")
	flag.StringVar(&logLevelStr, "logLevel", logLevelStr, "Log Level: debug, info, warn, and error")
	flag.IntVar(&maxParentDepth, "maxParentDepth", maxParentDepth, "Max process tree depth")
	flag.IntVar(&maxListProcessThreads, "maxListProcessThreads", maxListProcessThreads, "Max threads to get current processes")
	flag.StringVar(&root, "root", root, "The root location")
	flag.Var(&ignoreSourceComm, "ignoreSourceComm", "Ignore source comm (binary name), can be specified multiple times")
	flag.Parse()

	err := logLevel.UnmarshalText([]byte(logLevelStr))
	if err != nil {
		log.Fatalf("invalid log level: %s", err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// Catch termination signals because we must clean up before exiting.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// For pre-5.11 kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	defer slog.Info("All resources cleaned up")

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Load our ebpf program to trace sys_kill.
	kp, err := link.Tracepoint("syscalls", "sys_enter_kill", objs.TpEnterKill, nil)
	if err != nil {
		objs.Close()
		log.Fatalf("Failed to open tracepoint: %s", err)
	}
	defer kp.Close()

	// Read from ebpf ring buffer.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		kp.Close()
		log.Fatalf("Failed to open ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the ringbuf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		defer slog.Info("Received stop signal, exiting...")

		if err := rd.Close(); err != nil {
			slog.Error("Failed to close ringbuf reader", "err", err)
		}
	}()

	slog.Info("Listening for events")

	// List (in the background) and cache current processes. We will use this cache
	// to get info (cmdline, comm, ppid) about a process and build the process tree.
	processCache := NewProcessCache()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Error("failed to read from ringbuf", "err", err)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("failed to parse bpf event", "err", err)
			continue
		}

		// Transform some strings.
		var sourceComm strings.Builder
		for i := 0; i < len(event.SourceComm); i++ {
			if event.SourceComm[i] != 0 {
				sourceComm.WriteByte(byte(event.SourceComm[i]))
			}
		}
		// Ignore certain comm (if specified).
		if slices.Contains(ignoreSourceComm, sourceComm.String()) {
			slog.Debug("ignored", "source.comm", sourceComm.String())
			continue
		}

		var sourceCmdlineRaw bytes.Buffer
		for i := 0; i < len(event.SourceCmdline); i++ {
			sourceCmdlineRaw.WriteByte(byte(event.SourceCmdline[i]))
		}
		sourceCmdline := cmdlineConv(sourceCmdlineRaw.Bytes())

		// Get the string representation about the signal if possible.
		sigstr := ""
		if event.Signal > 0 {
			sigstr = syscall.Signal(event.Signal).String()
		}

		log := slog.With("signal", event.Signal, "signalString", sigstr)
		// We have received process info from kernel space, use this instead of cached one.
		processCache.Insert(&Process{
			PID:     event.SourcePid,
			Cmdline: sourceCmdline,
			Comm:    sourceComm.String(),
			PPID:    event.SourcePpid,
		})
		log = log.With(slogProcessTreeGroup(processCache, "source", event.SourcePid, maxParentDepth))
		log = log.With(slogProcessTreeGroup(processCache, "target", event.TargetPid, maxParentDepth))

		log.Info("snooped signal")
	}
}

func slogProcessTreeGroup(cc *ProcessCache, key string, initialPid int64, maxDepth int) slog.Attr {
	depth := 0
	return slog.Group(key, processToSlogAttr(cc, initialPid, &depth, maxDepth)...)
}

func processToSlogAttr(cc *ProcessCache, pid int64, depth *int, maxDepth int) []any {
	p := cc.Lookup(pid)
	// If not found on /proc, at least tell the user pid.
	if p == nil {
		return []any{"pid", pid}
	}

	ret := []any{}
	if p.PID > 0 {
		ret = append(ret, "pid", p.PID)
	}
	if len(p.Cmdline) > 0 {
		ret = append(ret, "cmdline", p.Cmdline)
	}
	if len(p.Comm) > 0 {
		ret = append(ret, "comm", p.Comm)
	}

	*depth += 1
	if *depth >= maxDepth {
		return ret
	}

	// Recursively find parent.
	return append(ret, slog.Group("parent", processToSlogAttr(cc, p.PPID, depth, maxDepth)...))
}
