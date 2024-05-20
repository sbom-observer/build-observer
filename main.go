// Copyright 2024 Bitfront AB - All rights reserved
// Author: Andreas Bielk
package main

import (
	_ "embed"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//go:embed traceopens.bt
var bpftraceScript []byte

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "build-observer -u user -- command",
	//Short:   "TODO: Add a short description here",
	//Long:    `TODO: Add a longer description here`,
	Run:     RunWithBpftrace,
	Example: `sudo build-observer --user vagrant -- make -f Makefile.linux build-examples`,
	Version: version,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.Flags().StringP("output", "o", "build-observations.out", "Output filename")
	rootCmd.Flags().StringP("user", "u", "", "Run command as user")
}

func RunWithBpftrace(cmd *cobra.Command, args []string) {
	if syscall.Getuid() != 0 {
		fmt.Println("build-observer currently only supports running as the root user. Please run with sudo.")
		os.Exit(1)
	}

	if len(args) == 0 {
		fmt.Println("Please provide a command to trace as an argument (i.e. build-observer -u ci '/usr/bin/make').")
		os.Exit(1)
	}

	// write script slice to tempfile
	scriptFileName := filepath.Join(os.TempDir(), "traceopens.bt")
	err := os.WriteFile(scriptFileName, bpftraceScript, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %s\n", err)
		os.Exit(1)
	}

	user := cmd.Flag("user").Value.String()
	output := cmd.Flag("output").Value.String()
	target := strings.Join(args, " ")

	var bpftraceArgs []string
	if user == "" {
		bpftraceArgs = []string{"/usr/bin/bpftrace", "-o", output, "-c", target, scriptFileName}
	} else {
		bpftraceArgs = []string{"/usr/bin/bpftrace", "-q", "--no-warning", "-o", output, "-c", fmt.Sprintf("/usr/bin/sudo -u %s %s", user, target), scriptFileName}
	}

	err = syscall.Exec("/usr/bin/bpftrace", bpftraceArgs, os.Environ())
	if err != nil {
		fmt.Printf("Error execing: %s\n", err)
		os.Exit(1)
	}
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
