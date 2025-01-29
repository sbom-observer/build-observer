package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	fn := "/lib/x86_64-linux-gnu/libc.so.6"
	matched, err := filepath.Match("*.so.6", fn)
	if err != nil {
		fmt.Printf("Error matching glob pattern: %v\n", err)
		return
	}
	fmt.Println(matched)
}
