package types

import "time"

// BuildObservations is the "spec" for the output file
type BuildObservations struct {
	Start            time.Time `json:"start"`
	Stop             time.Time `json:"stop"`
	WorkingDirectory string    `json:"workingDirectory"`
	FilesOpened      []string  `json:"opened,omitempty"`
	FilesExecuted    []string  `json:"executed,omitempty"`
}
