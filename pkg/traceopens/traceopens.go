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
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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
	Dirfd    int32
	Comm     [MaxCommLen]byte
	Filename [MaxPathLen]byte
	Type     uint8
}

const EVENT_TYPE_EXEC = 1
const EVENT_TYPE_OPEN = 2

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

func TraceCommand(args []string, downgradeToUser string) (*TraceCommandResult, error) {
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

	// If we are running as root, and a user is specified, downgrade to that user
	if downgradeToUser != "" && syscall.Getuid() == 0 {
		log.Println("Running as root, downgrading to user", downgradeToUser)
		user, err := user.Lookup(downgradeToUser)
		if err != nil {
			log.Fatalln("User '"+downgradeToUser+"' not found or other error:", err)
		}

		uid, _ := strconv.ParseInt(user.Uid, 10, 32)
		gid, _ := strconv.ParseInt(user.Gid, 10, 32)

		err = syscall.Setgid(int(gid))
		if err != nil {
			log.Fatalf("Unable to set GID due to error: %v", err)
		}
		err = syscall.Setuid(int(uid))
		if err != nil {
			log.Fatalf("Unable to set UID due to error: %v", err)
		}
	}

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
			// comm := bytesToString(event.Comm[:]) // TODO: revisit if we need this
			filename := bytesToString(event.Filename[:])

			switch event.Type {
			case EVENT_TYPE_EXEC:
				resolvedPath := resolvePath(event.Pid, -100, filename)
				filesExecuted[resolvedPath] = struct{}{}
			case EVENT_TYPE_OPEN:
				resolvedPath := resolvePath(event.Pid, event.Dirfd, filename)
				filesOpened[resolvedPath] = struct{}{}
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

	resultOpened := slices.Collect(maps.Keys(filesOpened))
	resultExecuted := slices.Collect(maps.Keys(filesExecuted))

	for i := range resultOpened {
		resultOpened[i] = filepath.Clean(resultOpened[i])
	}

	for i := range resultExecuted {
		resultExecuted[i] = filepath.Clean(resultExecuted[i])
	}

	return &TraceCommandResult{
		Start:         start,
		Stop:          stop,
		FilesOpened:   resultOpened,
		FilesExecuted: resultExecuted,
	}, nil
}
