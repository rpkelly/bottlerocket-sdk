package integration

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// TestUtil provides common test utilities to eliminate code duplication
type TestUtil struct{}

// CreateTempDir creates a temporary directory with the given prefix
func (tu *TestUtil) CreateTempDir(prefix string) (string, error) {
	return os.MkdirTemp("", prefix)
}

// CopyFile copies a file from src to dst using streaming copy
func (tu *TestUtil) CopyFile(src, dst string) error {
	// Validate paths to prevent directory traversal
	if err := tu.validatePath(src); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	if err := tu.validatePath(dst); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := srcFile.Close(); err != nil {
			slog.Warn("Failed to close source file", "error", err)
		}
	}()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if err := dstFile.Close(); err != nil {
			slog.Warn("Failed to close destination file", "error", err)
		}
	}()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (tu *TestUtil) validatePath(path string) error {
	cleanPath := filepath.Clean(path)

	// For test scenarios, we need to be more permissive while still preventing
	// obvious malicious patterns. We'll allow relative paths that go up the tree
	// but reject paths that try to access system directories or go too far up.

	// Reject paths that try to access system directories
	systemPaths := []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/tmp/", "/root/", "/home/"}
	for _, sysPath := range systemPaths {
		if strings.HasPrefix(cleanPath, sysPath) && !strings.HasPrefix(cleanPath, "/tmp/") {
			return fmt.Errorf("path accesses system directory: %s", path)
		}
	}

	// Reject paths with excessive directory traversal (more than 3 levels up)
	if strings.Count(cleanPath, "../") > 3 {
		return fmt.Errorf("excessive directory traversal in path: %s", path)
	}

	// Reject paths with null bytes or other suspicious characters
	if strings.ContainsAny(cleanPath, "\x00") {
		return fmt.Errorf("path contains null bytes: %s", path)
	}

	return nil
}

// CleanupTempDir removes a temporary directory
func (tu *TestUtil) CleanupTempDir(dir string) error {
	if dir != "" {
		return os.RemoveAll(dir)
	}
	return nil
}

// WrapError creates a wrapped error with consistent formatting
func (tu *TestUtil) WrapError(operation, resource string, err error) error {
	return fmt.Errorf("failed to %s %s: %w", operation, resource, err)
}

// FileOperationError creates a file operation error
func (tu *TestUtil) FileOperationError(operation, path string, err error) error {
	return fmt.Errorf("failed to %s file %s: %w", operation, path, err)
}
