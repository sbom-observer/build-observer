package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang traceopens ../../bpf/traceopens.bpf.c -- -I../../bpf/headers

func bytesToString(buf []byte) string {
	i := bytes.IndexByte(buf, 0)
	if i == -1 {
		i = len(buf)
	}
	return string(buf[:i])
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <command> [args...]", os.Args[0])
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
	fmt.Printf("start %v", time.Now().Format(time.UnixDate))

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
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
	go func() {
		filesOpened := map[string]struct{}{}
		filesExecuted := map[string]struct{}{}

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
			comm := bytesToString(event.Comm[:])
			filename := bytesToString(event.Filename[:])

			switch event.Type {
			case 1:
				fmt.Printf("exec\t%s\n", filename)
				filesExecuted[filename] = struct{}{}
			case 2:
				fmt.Printf("open\t%s\t%s\n", comm, filename)
				filesOpened[filename] = struct{}{}
			}
		}

		// print all files that were opened but not executed
		// fmt.Println("--------------------------------")
		// for filename := range filesOpened {
		// 	if _, ok := filesExecuted[filename]; !ok {
		// 		fmt.Printf("open\t%s\n", filename)
		// 	}
		// }

		// // print all files that were executed but not opened
		// fmt.Println("--------------------------------")
		// for filename := range filesExecuted {
		// 	if _, ok := filesOpened[filename]; !ok {
		// 		fmt.Printf("exec\t%s\n", filename)
		// 	}
		// }
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
			fmt.Printf("Child process exited with status 0\n")
			break
		}
	}

	fmt.Printf("stop %v", time.Now().Format(time.UnixDate))
}
