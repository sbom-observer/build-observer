package traceopens

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// These constants need to match the C version
const (
	MaxPathLen = 256
	MaxCommLen = 16
)

// Event matches the C structure
type Event struct {
	Pid      uint32
	Ppid     uint32
	Comm     [MaxCommLen]byte
	Filename [MaxPathLen]byte
	Type     uint8
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang traceopens ../../bpf/traceopens.bpf.c -- -I../../bpf/headers

func bytesToString(buf []byte) string {
	i := bytes.IndexByte(buf, 0)
	if i == -1 {
		i = len(buf)
	}
	return string(buf[:i])
}

type TraceCommandResult struct {
	FilesOpened   []string
	FilesExecuted []string
	Start         time.Time
	Stop          time.Time
}

func TraceCommand(args []string) (*TraceCommandResult, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("command is required")
	}

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel
	objs := traceopensObjects{}
	if err := loadTraceopensObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoints
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		log.Fatalf("Opening fork tracepoint: %v", err)
	}
	defer tpFork.Close()

	tpEnterExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecveEnter, nil)
	if err != nil {
		log.Fatalf("Opening execve enter tracepoint: %v", err)
	}
	defer tpEnterExecve.Close()

	tpExitExecve, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.HandleExecveExit, nil)
	if err != nil {
		log.Fatalf("Opening execve exit tracepoint: %v", err)
	}
	defer tpExitExecve.Close()

	tpEnterOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenatEnter, nil)
	if err != nil {
		log.Fatalf("Opening openat enter tracepoint: %v", err)
	}
	defer tpEnterOpenat.Close()

	tpExitOpenat, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleOpenatExit, nil)
	if err != nil {
		log.Fatalf("Opening openat exit tracepoint: %v", err)
	}
	defer tpExitOpenat.Close()

	// Create ring buffer
	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Creating ring buffer reader: %v", err)
	}
	defer rb.Close()

	// Start the command
	start := time.Now()

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("Starting command: %v", err)
	}

	// Add child PID to map
	if err := objs.Pids.Put(uint32(cmd.Process.Pid), uint8(1)); err != nil {
		log.Fatalf("Adding PID to map: %v", err)
	}

	// Set up signal handling
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Process events
	filesOpened := map[string]struct{}{}
	filesExecuted := map[string]struct{}{}

	go func() {
		var event Event
		for {
			record, err := rb.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					//log.Printf("Error (ringbuf.ErrClosed) reading from ring buffer: %v", err)
					break
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// Parse the event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			// Convert null-terminated strings to Go strings
			// comm := bytesToString(event.Comm[:])
			filename := bytesToString(event.Filename[:])

			switch event.Type {
			case 1:
				// fmt.Printf("exec\t%s\n", filename)
				filesExecuted[filename] = struct{}{}
			case 2:
				// fmt.Printf("open\t%s\t%s\n", comm, filename)
				filesOpened[filename] = struct{}{}
			}
		}
	}()

	// Wait for command to finish or signal
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-stopper:
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Error killing process: %v", err)
		}
		<-done
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				fmt.Printf("Child process exited with status %d\n", exitErr.ExitCode())
				break
			} else {
				log.Printf("Error waiting for command: %v", err)
				break
			}
		} else {
			// fmt.Printf("Child process exited with status 0\n")
			break
		}
	}

	stop := time.Now()

	return &TraceCommandResult{
		Start:         start,
		Stop:          stop,
		FilesOpened:   slices.Collect(maps.Keys(filesOpened)),
		FilesExecuted: slices.Collect(maps.Keys(filesExecuted)),
	}, nil
}
