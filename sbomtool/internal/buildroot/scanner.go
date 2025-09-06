// Package buildroot provides utilities for scanning and analyzing buildroot directory structures.
//
// The package implements efficient recursive directory traversal with configurable depth limits,
// file type detection, and path normalization for integration with Syft's file coordinate system.
package buildroot

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scanner provides comprehensive buildroot directory scanning functionality.
// It implements efficient recursive directory traversal with configurable depth limits,
// file type detection, and path normalization for integration with Syft's file coordinate system.
type Scanner struct {
	pathNormalizer  *PathNormalizer
	maxDepth        int
	excludePatterns []string
}

// ScanResult contains the complete results of a buildroot directory scan.
// It includes categorized file lists, normalized paths for Syft compatibility,
// and performance metrics from the scanning operation.
type ScanResult struct {
	AllFiles        []string
	RegularFiles    []string
	SymbolicLinks   []string
	Directories     []string
	NormalizedPaths map[string]string // buildroot path -> installed path
	TotalSize       int64
	ScanDuration    time.Duration
}

// NewScanner creates a new buildroot scanner with the specified configuration.
func NewScanner(maxDepth int, excludePatterns []string) *Scanner {
	return &Scanner{
		pathNormalizer:  NewPathNormalizer(),
		maxDepth:        maxDepth,
		excludePatterns: excludePatterns,
	}
}

// ScanDirectory performs comprehensive recursive scanning of the buildroot directory.
//
// It discovers all files, categorizes them by type, and normalizes paths for Syft compatibility.
// The scan respects depth limits and exclusion patterns to optimize performance.
func (s *Scanner) ScanDirectory(buildrootPath string) (*ScanResult, error) {
	startTime := time.Now()

	// Verify buildroot exists and is accessible
	if _, err := os.Stat(buildrootPath); err != nil {
		return nil, fmt.Errorf("buildroot path not accessible: %w", err)
	}

	result := &ScanResult{
		AllFiles:        make([]string, 0),
		RegularFiles:    make([]string, 0),
		SymbolicLinks:   make([]string, 0),
		Directories:     make([]string, 0),
		NormalizedPaths: make(map[string]string),
	}

	err := s.scanRecursive(buildrootPath, 0, result)
	if err != nil {
		return nil, fmt.Errorf("failed to scan buildroot: %w", err)
	}

	// Normalize all paths for Syft compatibility
	for _, filePath := range result.AllFiles {
		normalized, err := s.pathNormalizer.BuildrootToInstalled(filePath, buildrootPath)
		if err != nil {
			slog.Warn("Failed to normalize path", "path", filePath, "error", err)
			continue
		}
		result.NormalizedPaths[filePath] = normalized
	}

	result.ScanDuration = time.Since(startTime)

	slog.Info("Buildroot scan completed",
		"path", buildrootPath,
		"total_files", len(result.AllFiles),
		"regular_files", len(result.RegularFiles),
		"symbolic_links", len(result.SymbolicLinks),
		"directories", len(result.Directories),
		"normalized_paths", len(result.NormalizedPaths),
		"total_size_mb", result.TotalSize/(1024*1024),
		"duration_ms", result.ScanDuration.Milliseconds())

	return result, nil
}

// GetNormalizedPaths extracts normalized paths from scan results for Syft file coordinate matching.
func (s *Scanner) GetNormalizedPaths(scanResult *ScanResult) []string {
	var normalizedPaths []string
	for _, normalized := range scanResult.NormalizedPaths {
		normalizedPaths = append(normalizedPaths, normalized)
	}
	return normalizedPaths
}

// scanRecursive performs recursive directory scanning with depth control.
func (s *Scanner) scanRecursive(currentPath string, depth int, result *ScanResult) error {
	if depth > s.maxDepth {
		return nil
	}

	entries, err := os.ReadDir(currentPath)
	if err != nil {
		slog.Warn("Failed to read directory", "path", currentPath, "error", err)
		return nil // Continue scanning other directories
	}

	for _, entry := range entries {
		fullPath := filepath.Join(currentPath, entry.Name())

		// Check exclusion patterns before processing
		if s.shouldExclude(fullPath) {
			continue
		}

		// Get file info for detailed analysis
		info, err := entry.Info()
		if err != nil {
			slog.Warn("Failed to get file info", "path", fullPath, "error", err)
			continue
		}

		result.TotalSize += info.Size()
		result.AllFiles = append(result.AllFiles, fullPath)

		// Categorize by file type
		switch {
		case info.Mode().IsRegular():
			result.RegularFiles = append(result.RegularFiles, fullPath)

		case info.Mode()&os.ModeSymlink != 0:
			result.SymbolicLinks = append(result.SymbolicLinks, fullPath)

		case info.IsDir():
			result.Directories = append(result.Directories, fullPath)
			// Recurse into subdirectory
			if err := s.scanRecursive(fullPath, depth+1, result); err != nil {
				return err
			}
		}
	}

	return nil
}

// shouldExclude checks if a path should be excluded from scanning based on configured patterns.
func (s *Scanner) shouldExclude(path string) bool {
	for _, pattern := range s.excludePatterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

// PathNormalizer handles conversion from buildroot paths to installed paths.
// It provides utilities for stripping buildroot prefixes and normalizing paths
// for compatibility with Syft's file coordinate system.
type PathNormalizer struct {
	// Common buildroot prefixes to strip
	buildrootPrefixes []string
}

// NewPathNormalizer creates a new path normalizer with common buildroot prefixes.
func NewPathNormalizer() *PathNormalizer {
	return &PathNormalizer{
		buildrootPrefixes: []string{
			"/buildroot",
			"/tmp/buildroot",
			"/build/buildroot",
		},
	}
}

// BuildrootToInstalled converts a buildroot path to an installed path for Syft coordinate matching.
//
// It removes the buildroot prefix and ensures the path starts with "/" for consistency
// with Syft's file coordinate system.
func (n *PathNormalizer) BuildrootToInstalled(buildrootFile, buildrootPath string) (string, error) {
	// Remove buildroot prefix to get installed path
	if !strings.HasPrefix(buildrootFile, buildrootPath) {
		return "", fmt.Errorf("file %s is not under buildroot %s", buildrootFile, buildrootPath)
	}

	// Strip buildroot prefix
	relativePath := strings.TrimPrefix(buildrootFile, buildrootPath)

	// Ensure path starts with /
	if !strings.HasPrefix(relativePath, "/") {
		relativePath = "/" + relativePath
	}

	// Clean the path for Syft compatibility
	installedPath := filepath.Clean(relativePath)

	return installedPath, nil
}
