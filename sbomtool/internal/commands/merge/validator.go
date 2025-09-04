// Package merge provides validation functionality for merge operations.
package merge

import (
	"fmt"
	"os"
	"path/filepath"
)

// MergeValidationError represents validation errors specific to merge operations.
type MergeValidationError struct {
	Field      string
	Message    string
	Suggestion string
}

func (e *MergeValidationError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s: %s (suggestion: %s)", e.Field, e.Message, e.Suggestion)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateInputFiles validates that all input files exist and are readable.
func ValidateInputFiles(files []string) error {
	for _, file := range files {
		if err := validateSingleFile(file); err != nil {
			return &MergeValidationError{
				Field:      "input_files",
				Message:    fmt.Sprintf("file %s: %v", file, err),
				Suggestion: "ensure file exists and is readable",
			}
		}
	}
	return nil
}

// ValidateOutputPath validates that the output path is writable.
func ValidateOutputPath(outputPath string) error {
	dir := filepath.Dir(outputPath)

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return &MergeValidationError{
			Field:      "output_path",
			Message:    fmt.Sprintf("directory %s does not exist", dir),
			Suggestion: "create the directory or use an existing path",
		}
	}

	// Check if we can write to the directory
	testFile := filepath.Join(dir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return &MergeValidationError{
			Field:      "output_path",
			Message:    fmt.Sprintf("cannot write to directory %s: %v", dir, err),
			Suggestion: "check directory permissions",
		}
	}

	// Clean up test file
	_ = os.Remove(testFile) // Ignore cleanup errors as they don't affect validation result
	return nil
}

// validateSingleFile checks if a single file exists and is readable.
func validateSingleFile(file string) error {
	info, err := os.Stat(file)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist")
	}
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file")
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	return nil
}
