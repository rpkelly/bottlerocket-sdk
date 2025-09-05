// Package deduplication provides reusable package deduplication logic for SBOM operations.
//
// The deduplication strategy uses CPE (Common Platform Enumeration) as the primary key
// for identifying duplicate packages, with fallback to name+version+type for packages
// without CPE information.
package deduplication

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

// Deduplicator handles package deduplication with relationship preservation.
type Deduplicator struct {
	config DeduplicationConfig
}

// DeduplicationConfig holds configuration for deduplication operations.
type DeduplicationConfig struct {
	PreferCPE        bool   // Prioritize CPE-based deduplication
	CPENormalization bool   // Apply CPE normalization rules
	FallbackStrategy string // "name_version_type" or "strict_cpe_only"
	MetadataMerging  bool   // Enable metadata consolidation
	PreserveSources  bool   // Track original package sources
}

// DeduplicationResult contains the results of package deduplication.
type DeduplicationResult struct {
	CanonicalPackages map[string]*pkg.Package // canonical key -> package
	IDMapping         map[string]string       // old package ID -> canonical package ID
	CPEMapping        map[string]string       // CPE -> canonical package ID
	Statistics        DeduplicationStats
	ProcessingLog     []DeduplicationEvent
}

// DeduplicationStats provides metrics about the deduplication process.
type DeduplicationStats struct {
	InputPackages        int
	OutputPackages       int
	DeduplicatedCount    int
	CPEBasedMatches      int
	FallbackMatches      int
	RelationshipsUpdated int
	ProcessingTime       time.Duration
}

// DeduplicationEvent represents a single event during deduplication processing.
type DeduplicationEvent struct {
	Type       string // "cpe_match", "fallback_match", "packages_merged"
	Timestamp  time.Time
	PackageIDs []string
	CPE        string // For CPE-based matches
	Details    map[string]interface{}
}

// NewDeduplicator creates a new deduplicator with the specified configuration.
func NewDeduplicator(config DeduplicationConfig) *Deduplicator {
	return &Deduplicator{config: config}
}

// DeduplicatePackages performs deduplication on a slice of packages.
func (d *Deduplicator) DeduplicatePackages(packages []pkg.Package) *DeduplicationResult {
	startTime := time.Now()

	result := &DeduplicationResult{
		CanonicalPackages: make(map[string]*pkg.Package),
		IDMapping:         make(map[string]string),
		CPEMapping:        make(map[string]string),
		ProcessingLog:     make([]DeduplicationEvent, 0),
		Statistics: DeduplicationStats{
			InputPackages: len(packages),
		},
	}

	keyToPackages := make(map[string][]*pkg.Package)

	// Group packages by canonical key
	for i := range packages {
		p := &packages[i]
		key := d.generateCanonicalKey(*p)
		keyToPackages[key] = append(keyToPackages[key], p)
	}

	// Process each group
	for key, pkgGroup := range keyToPackages {
		canonical := d.selectCanonicalPackage(pkgGroup)

		if d.config.MetadataMerging && len(pkgGroup) > 1 {
			d.mergePackageMetadata(canonical, pkgGroup[1:])
		}

		result.CanonicalPackages[key] = canonical

		// Build ID mapping
		for _, p := range pkgGroup {
			result.IDMapping[string(p.ID())] = string(canonical.ID())
		}

		// Track CPE mapping
		if len(canonical.CPEs) > 0 {
			normalizedCPE := d.normalizeCPE(canonical.CPEs[0].Attributes.String())
			result.CPEMapping[normalizedCPE] = string(canonical.ID())
		}

		// Log deduplication event
		if len(pkgGroup) > 1 {
			event := DeduplicationEvent{
				Type:       d.getMatchType(*canonical),
				Timestamp:  time.Now(),
				PackageIDs: make([]string, len(pkgGroup)),
			}

			for i, p := range pkgGroup {
				event.PackageIDs[i] = string(p.ID())
			}

			if len(canonical.CPEs) > 0 {
				event.CPE = canonical.CPEs[0].Attributes.String()
				result.Statistics.CPEBasedMatches++
			} else {
				result.Statistics.FallbackMatches++
			}

			result.ProcessingLog = append(result.ProcessingLog, event)
		}
	}

	result.Statistics.OutputPackages = len(result.CanonicalPackages)
	result.Statistics.DeduplicatedCount = result.Statistics.InputPackages - result.Statistics.OutputPackages
	result.Statistics.ProcessingTime = time.Since(startTime)

	slog.Debug("Package deduplication completed",
		"input_packages", result.Statistics.InputPackages,
		"output_packages", result.Statistics.OutputPackages,
		"deduplicated_count", result.Statistics.DeduplicatedCount,
		"cpe_matches", result.Statistics.CPEBasedMatches,
		"fallback_matches", result.Statistics.FallbackMatches,
		"processing_time", result.Statistics.ProcessingTime)

	return result
}

// UpdateRelationships updates relationships using the ID mapping from deduplication.
func (d *Deduplicator) UpdateRelationships(relationships []artifact.Relationship, idMapping map[string]string) []artifact.Relationship {
	updated := make([]artifact.Relationship, 0, len(relationships))
	relationshipSet := make(map[string]bool)

	for _, rel := range relationships {
		newRel := rel

		// Update From reference
		if canonicalID, exists := idMapping[string(rel.From.ID())]; exists {
			newRel.From = d.updatePackageReference(rel.From, canonicalID)
		}

		// Update To reference
		if canonicalID, exists := idMapping[string(rel.To.ID())]; exists {
			newRel.To = d.updatePackageReference(rel.To, canonicalID)
		}

		// Create relationship key for deduplication
		relKey := fmt.Sprintf("%s|%s|%s", newRel.From.ID(), newRel.To.ID(), newRel.Type)

		if !relationshipSet[relKey] {
			relationshipSet[relKey] = true
			updated = append(updated, newRel)
		}
	}

	slog.Debug("Relationships updated",
		"input_relationships", len(relationships),
		"output_relationships", len(updated),
		"deduplicated_relationships", len(relationships)-len(updated))

	return updated
}

// generateCanonicalKey creates a unique key for package deduplication.
func (d *Deduplicator) generateCanonicalKey(p pkg.Package) string {
	// Use CPE as primary deduplication key when available
	if d.config.PreferCPE && len(p.CPEs) > 0 {
		return d.normalizeCPE(p.CPEs[0].Attributes.String())
	}

	// Fallback to name+version+type for packages without CPE
	name := strings.ToLower(strings.TrimSpace(p.Name))
	version := d.normalizeVersion(p.Version)
	pkgType := string(p.Type)

	return fmt.Sprintf("fallback:%s|%s|%s", name, version, pkgType)
}

// normalizeCPE normalizes CPE strings for consistent matching.
func (d *Deduplicator) normalizeCPE(cpe string) string {
	if !d.config.CPENormalization {
		return cpe
	}

	// Remove cpe: prefix if present
	normalized := strings.TrimPrefix(cpe, "cpe:")

	// Ensure consistent format (cpe:2.3 standard)
	if !strings.HasPrefix(normalized, "2.3:") {
		normalized = d.convertLegacyCPE(normalized)
	}

	// Normalize case and whitespace
	return strings.ToLower(strings.TrimSpace(normalized))
}

// normalizeVersion normalizes version strings for consistent matching.
func (d *Deduplicator) normalizeVersion(version string) string {
	if version == "" {
		return "unknown"
	}
	return strings.ToLower(strings.TrimSpace(version))
}

// convertLegacyCPE converts legacy CPE formats to CPE 2.3 standard.
func (d *Deduplicator) convertLegacyCPE(cpe string) string {
	// Basic conversion - in practice this would be more sophisticated
	if !strings.HasPrefix(cpe, "2.3:") {
		return "2.3:" + cpe
	}
	return cpe
}

// selectCanonicalPackage chooses the canonical package from a group of duplicates.
func (d *Deduplicator) selectCanonicalPackage(packages []*pkg.Package) *pkg.Package {
	if len(packages) == 1 {
		return packages[0]
	}

	// Priority order:
	// 1. Package with CPE takes precedence over those without
	// 2. Package with most complete metadata
	// 3. First occurrence

	var canonical *pkg.Package
	maxScore := -1

	for _, p := range packages {
		score := d.calculatePackageCompleteness(*p)
		if score > maxScore {
			maxScore = score
			canonical = p
		}
	}

	return canonical
}

// calculatePackageCompleteness scores package completeness for canonical selection.
func (d *Deduplicator) calculatePackageCompleteness(p pkg.Package) int {
	score := 0
	// Note: Files field may not be available in all Syft versions
	// score += len(p.Files) * 2    // Files are important
	score += len(p.Licenses.ToUnorderedSlice()) // License info
	score += len(p.CPEs) * 3                    // CPEs are very important
	if p.Version != "" {
		score += 5 // Version info
	}
	return score
}

// mergePackageMetadata merges metadata from duplicate packages into the canonical package.
func (d *Deduplicator) mergePackageMetadata(canonical *pkg.Package, duplicates []*pkg.Package) {
	if !d.config.MetadataMerging {
		return
	}

	// Merge CPEs (union, deduplicated)
	cpeSet := make(map[string]cpe.CPE)

	// Add canonical package CPEs
	for _, c := range canonical.CPEs {
		normalizedCPE := d.normalizeCPE(c.Attributes.String())
		cpeSet[normalizedCPE] = c
	}

	// Add CPEs from duplicates
	for _, dup := range duplicates {
		for _, c := range dup.CPEs {
			normalizedCPE := d.normalizeCPE(c.Attributes.String())
			if _, exists := cpeSet[normalizedCPE]; !exists {
				cpeSet[normalizedCPE] = c
			}
		}
	}

	// Convert back to slice
	canonical.CPEs = make([]cpe.CPE, 0, len(cpeSet))
	for _, c := range cpeSet {
		canonical.CPEs = append(canonical.CPEs, c)
	}

	// Merge licenses
	d.mergeLicenses(canonical, duplicates)
}

// mergeLicenses merges license information from duplicate packages.
func (d *Deduplicator) mergeLicenses(canonical *pkg.Package, duplicates []*pkg.Package) {
	licenseSet := make(map[string]pkg.License)

	// Add canonical licenses
	for _, license := range canonical.Licenses.ToUnorderedSlice() {
		licenseSet[license.Value] = license
	}

	// Add licenses from duplicates
	for _, dup := range duplicates {
		for _, license := range dup.Licenses.ToUnorderedSlice() {
			if _, exists := licenseSet[license.Value]; !exists {
				licenseSet[license.Value] = license
			}
		}
	}

	// Convert back to LicenseSet
	licenses := make([]pkg.License, 0, len(licenseSet))
	for _, license := range licenseSet {
		licenses = append(licenses, license)
	}
	canonical.Licenses = pkg.NewLicenseSet(licenses...)
}

// updatePackageReference updates a package reference with a new canonical ID.
func (d *Deduplicator) updatePackageReference(ref artifact.Identifiable, canonicalID string) artifact.Identifiable {
	// This is a simplified implementation - in practice would need to handle
	// different types of package references properly
	return ref
}

// getMatchType determines the type of match used for deduplication.
func (d *Deduplicator) getMatchType(p pkg.Package) string {
	if len(p.CPEs) > 0 {
		return "cpe_match"
	}
	return "fallback_match"
}
