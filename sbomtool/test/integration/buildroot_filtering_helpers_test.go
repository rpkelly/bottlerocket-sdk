package integration

import (
	"os"
	"path/filepath"
)

// Helper methods for test data creation

// createBuildrootWithFiles creates a buildroot directory with specified files
func (tc *buildrootFilteringTestContext) createBuildrootWithFiles(buildrootDir string, files []string) error {
	for _, file := range files {
		fullPath := filepath.Join(buildrootDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, []byte("test content"), 0644); err != nil {
			return err
		}
	}
	return nil
}
