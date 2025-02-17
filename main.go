// Copyright 2024 Bitfront AB - All rights reserved
// Author: Andreas Bielk
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/sbom-observer/build-observer/pkg/traceopens"
	"github.com/sbom-observer/build-observer/pkg/types"
	"github.com/spf13/cobra"
	"os"
	"sort"
	"strings"
	"syscall"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "build-observer -- [command]",
	//Short:   "TODO: Add a short description here",
	//Long:    `TODO: Add a longer description here`,
	Run:     RunWithBpftrace,
	Example: `sudo build-observer -- make`,
	Version: version,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.Flags().StringP("output", "o", "build-observations.json", "Output filename")
	rootCmd.Flags().StringSliceP("exclude", "e", []string{".", "..", "*.so", "*.so.6", "*.so.2", "*.a", "/etc/ld.so.cache"}, "Exclude files from output")
	// rootCmd.Flags().StringP("user", "u", "", "Run command as user")
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

	result, err := traceopens.TraceCommand(args)
	if err != nil {
		fmt.Printf("Error tracing command: %s\n", err)
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current working directory: %s\n", err)
		os.Exit(1)
	}

	buildObservations := types.BuildObservations{
		Start:            result.Start,
		Stop:             result.Stop,
		FilesOpened:      result.FilesOpened,
		FilesExecuted:    result.FilesExecuted,
		WorkingDirectory: cwd,
	}

	// sort filesOpened and filesExecuted
	sort.Strings(buildObservations.FilesOpened)
	sort.Strings(buildObservations.FilesExecuted)

	// filter out files that match the exclude pattern
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	for _, pattern := range exclude {
		buildObservations.FilesOpened = Filter(buildObservations.FilesOpened, func(s string) bool {
			if strings.HasPrefix(pattern, "*") {
				return !strings.HasSuffix(s, pattern[1:])
			}
			return s != pattern
		})
		buildObservations.FilesExecuted = Filter(buildObservations.FilesExecuted, func(s string) bool {
			if strings.HasPrefix(pattern, "*") {
				return !strings.HasSuffix(s, pattern[1:])
			}
			return s != pattern
		})
	}

	// write result to output file as json
	output := cmd.Flag("output").Value.String()
	out, err := os.Create(output)
	if err != nil {
		fmt.Printf("Error creating output file: %s\n", err)
		os.Exit(1)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.Encode(buildObservations)
	fmt.Printf("Wrote build observations to %s\n", output)
}

func Filter[T any](slice []T, f func(T) bool) []T {
	var n []T
	for _, e := range slice {
		if f(e) {
			n = append(n, e)
		}
	}
	return n
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
