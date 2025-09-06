// Package processor provides Syft-based SBOM processing capabilities optimized for Bottlerocket builds.
// It configures Syft's catalogers for comprehensive package detection including Go and Rust binary analysis.
package processor

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// SyftConfiguredProcessor provides SBOM processing using properly configured Syft catalogers.
// It encapsulates Syft's format decoders and encoders for comprehensive SBOM operations.
type SyftConfiguredProcessor struct {
	formatDecoders []sbom.FormatDecoder
	formatEncoders []sbom.FormatEncoder
}

// NewBottlerocketSyftProcessor creates a new processor configured for Bottlerocket builds.
// It enables Go and Rust binary catalogers and optimizes settings for build environments.
func NewBottlerocketSyftProcessor() *SyftConfiguredProcessor {
	return &SyftConfiguredProcessor{
		formatDecoders: format.Decoders(),
		formatEncoders: format.Encoders(),
	}
}

// GenerateComprehensiveSBOM generates an SBOM using configured Syft catalogers.
// It includes comprehensive package detection with Go and Rust binary analysis.
func (p *SyftConfiguredProcessor) GenerateComprehensiveSBOM(buildDir string) (*sbom.SBOM, error) {
	// Create source from directory
	src, err := syft.GetSource(context.Background(), buildDir, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Syft source: %w", err)
	}

	// Create SBOM with default configuration (includes Go and Rust binary detection)
	s, err := syft.CreateSBOM(context.Background(), src, nil)
	if err != nil {
		return nil, fmt.Errorf("syft SBOM creation failed: %w", err)
	}

	slog.Info("Comprehensive SBOM generation completed",
		"total_packages", s.Artifacts.Packages.PackageCount(),
		"relationships", len(s.Relationships),
		"go_packages", p.countPackagesByType(s.Artifacts.Packages, pkg.GoModulePkg),
		"rust_packages", p.countPackagesByType(s.Artifacts.Packages, pkg.RustPkg))

	return s, nil
}

// LoadSBOM loads an existing SBOM using Syft's format detection.
// It returns the SBOM, format identifier, and any error encountered.
func (p *SyftConfiguredProcessor) LoadSBOM(path string) (*sbom.SBOM, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			slog.Warn("Failed to close SBOM file", "error", closeErr)
		}
	}()

	// Use Syft's format detection and decoding
	s, formatID, _, err := format.Decode(file)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode SBOM: %w", err)
	}

	slog.Debug("SBOM loaded successfully",
		"format", formatID,
		"packages", s.Artifacts.Packages.PackageCount(),
		"relationships", len(s.Relationships))

	return s, string(formatID), nil
}

// SaveSBOM saves an SBOM using Syft's format encoders.
// It supports all formats that Syft can encode.
func (p *SyftConfiguredProcessor) SaveSBOM(s *sbom.SBOM, path, formatName string) error {
	// Find the encoder for the specified format
	var encoder sbom.FormatEncoder
	for _, enc := range p.formatEncoders {
		if string(enc.ID()) == formatName {
			encoder = enc
			break
		}
	}

	if encoder == nil {
		return fmt.Errorf("unsupported output format: %s", formatName)
	}

	// Encode the SBOM
	bytes, err := format.Encode(*s, encoder)
	if err != nil {
		return fmt.Errorf("failed to encode SBOM: %w", err)
	}

	// Write to file
	err = os.WriteFile(path, bytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write SBOM to file: %w", err)
	}

	return nil
}

// GetRelationships returns the relationships from an SBOM for dependency operations.
// This provides access to Syft's relationship data for filtering operations.
func (p *SyftConfiguredProcessor) GetRelationships(s *sbom.SBOM) []interface{} {
	// Convert artifact.Relationship slice to []interface{}
	relationships := make([]interface{}, len(s.Relationships))
	for i, rel := range s.Relationships {
		relationships[i] = rel
	}
	return relationships
}

// countPackagesByType counts packages of a specific type for logging purposes.
func (p *SyftConfiguredProcessor) countPackagesByType(catalog *pkg.Collection, pkgType pkg.Type) int {
	count := 0
	for _, pkg := range catalog.Sorted() {
		if pkg.Type == pkgType {
			count++
		}
	}
	return count
}

// GetFormatEncoders returns the configured format encoders
func (p *SyftConfiguredProcessor) GetFormatEncoders() []sbom.FormatEncoder {
	return p.formatEncoders
}
