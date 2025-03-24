package traceopens

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

type dirdfKey struct {
	pid   uint32
	dirfd int32
}

var dirfdCache = make(map[dirdfKey]string)

func resolvePath(pid uint32, dirfd int32, filename string) string {
	if len(filename) == 0 {
		return filename
	}

	// If it's an absolute path, return as is
	if filename[0] == '/' {
		return filename
	}

	// Check cache
	if cachedPath, ok := dirfdCache[dirdfKey{pid, dirfd}]; ok {
		return filepath.Join(cachedPath, filename)
	}

	// Handle AT_FDCWD (-100) - relative to current working directory
	if dirfd == -100 {
		cwdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			log.Printf("Warning: missed the lifetime of the current working directory for '%s': %v", filename, err)
			return filename
		}

		dirfdCache[dirdfKey{pid, dirfd}] = cwdPath

		return filepath.Join(cwdPath, filename)
	}

	// Try to resolve the directory FD
	fdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	if err != nil {
		log.Printf("Error resolving directory FD for '%s': %v", filename, err)

		// FALLBACK: we missed the lifetime of the FD, let's fallback to PATH and warn the user
		log.Printf("Warning: missed the lifetime of the directory FD (%d), falling back to lookup '%s' in PATH", dirfd, filename)
		executablePath, err := exec.LookPath(filename)
		if err != nil {
			log.Printf("Error resolving %s in PATH: %v", filename, err)
			return filename
		}

		return executablePath
	}

	dirfdCache[dirdfKey{pid, dirfd}] = fdPath

	return filepath.Clean(filepath.Join(fdPath, filename))
}
