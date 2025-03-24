package traceopens

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolvePath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Test only runs on Linux")
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "resolvepath_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test subdirectory
	testSubDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(testSubDir, 0755); err != nil {
		t.Fatalf("Failed to create test subdirectory: %v", err)
	}

	// Create a test file
	testFile := filepath.Join(testSubDir, "testfile.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name     string
		pid      uint32
		dirfd    int32
		filename string
		want     string
	}{
		{
			name:     "absolute path",
			pid:      1,
			dirfd:    0,
			filename: "/absolute/path/file.txt",
			want:     "/absolute/path/file.txt",
		},
		{
			name:     "empty filename",
			pid:      1,
			dirfd:    0,
			filename: "",
			want:     "",
		},
		{
			name:     "AT_FDCWD case",
			pid:      uint32(os.Getpid()),
			dirfd:    -100,
			filename: "relative/path.txt",
			want:     filepath.Join(mustGetwd(t), "relative/path.txt"),
		},
		{
			name:     "real dirfd case",
			pid:      uint32(os.Getpid()),
			dirfd:    getDirFd(t),
			filename: "some_file.txt",
			want:     filepath.Join(mustGetwd(t), "some_file.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the cache before each test
			dirfdCache = make(map[dirdfKey]string)

			got := resolvePath(tt.pid, tt.dirfd, tt.filename)
			if got != tt.want {
				t.Errorf("resolvePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to get current working directory
func mustGetwd(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	return cwd
}

func getDirFd(t *testing.T) int32 {
	t.Helper()
	dir, err := os.Open(".")
	if err != nil {
		t.Fatalf("Failed to open current directory: %v", err)
	}
	t.Cleanup(func() {
		dir.Close()
	})
	return int32(dir.Fd())
}
