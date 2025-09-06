// Package filter provides the core SBOM filtering engine that leverages Syft's relationship.Index
// for all dependency operations, performs buildroot-based filtering with transitive dependency
// resolution, and generates filtered SBOM output while maintaining Syft's format integrity.
package filter

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"

	"github.com/bottlerocket-os/bottlerocket-sdk/sbomtool/go/internal/buildroot"
	"github.com/bottlerocket-os/bottlerocket-sdk/sbomtool/go/internal/processor"
)

// FilteringEngine filters SBOMs based on buildroot contents with transitive dependency resolution.
type FilteringEngine struct {
	processor        *processor.SyftConfiguredProcessor
	buildrootScanner *buildroot.Scanner
}

// FilteringResult contains the complete results of the SBOM filtering operation.
// It includes the filtered SBOM, categorized packages, and comprehensive statistics
// about the filtering process.
type FilteringResult struct {
	FilteredSBOM     *sbom.SBOM
	RootPackages     []pkg.Package
	IncludedPackages []pkg.Package
	ExcludedPackages []pkg.Package
	Statistics       FilteringStatistics
}

// FilteringStatistics provides comprehensive metrics about the filtering operation.
// It includes counts of input/output packages and relationships, performance timing,
// and details about root matches and transitive inclusions.
type FilteringStatistics struct {
	InputPackages        int
	OutputPackages       int
	InputRelationships   int
	OutputRelationships  int
	FilteringDuration    time.Duration
	RootMatches          int
	TransitiveInclusions int
}

// NewFilteringEngine creates a new filtering engine with configured components.
// It initializes the Syft processor and buildroot scanner with appropriate settings
// for Bottlerocket build environments.
func NewFilteringEngine() *FilteringEngine {
	return &FilteringEngine{
		processor:        processor.NewBottlerocketSyftProcessor(),
		buildrootScanner: buildroot.NewScanner(10, []string{"*.tmp", "*.log"}),
	}
}

// FilterSBOMByBuildroot filters an SBOM based on buildroot contents with transitive dependency resolution.
func (e *FilteringEngine) FilterSBOMByBuildroot(
	inputSBOM *sbom.SBOM,
	buildrootPath string) (*FilteringResult, error) {

	startTime := time.Now()

	slog.Info("Starting SBOM filtering with Syft relationships",
		"input_packages", inputSBOM.Artifacts.Packages.PackageCount(),
		"input_relationships", len(inputSBOM.Relationships),
		"buildroot_path", buildrootPath)

	buildrootResult, err := e.buildrootScanner.ScanDirectory(buildrootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan buildroot: %w", err)
	}

	normalizedPaths := e.buildrootScanner.GetNormalizedPaths(buildrootResult)

	slog.Debug("Buildroot scanning completed",
		"total_files", len(buildrootResult.AllFiles),
		"normalized_paths", len(normalizedPaths))

	rootPackages, err := e.findPackagesWithBuildrootFiles(
		inputSBOM.Artifacts.Packages, normalizedPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to find root packages: %w", err)
	}

	slog.Info("Root packages identified",
		"root_count", len(rootPackages),
		"buildroot_files", len(normalizedPaths))

	includedPackages, err := e.resolveTransitiveDependencies(inputSBOM, rootPackages)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve transitive dependencies: %w", err)
	}

	slog.Info("Transitive dependency resolution completed",
		"root_packages", len(rootPackages),
		"total_included", len(includedPackages))

	filteredSBOM, err := e.createFilteredSBOM(inputSBOM, includedPackages)
	if err != nil {
		return nil, fmt.Errorf("failed to create filtered SBOM: %w", err)
	}

	if err := e.validateFilteredSBOM(filteredSBOM); err != nil {
		return nil, fmt.Errorf("filtered SBOM validation failed: %w", err)
	}

	allPackages := inputSBOM.Artifacts.Packages.Sorted()
	excludedPackages := e.getExcludedPackages(allPackages, includedPackages)

	result := &FilteringResult{
		FilteredSBOM:     filteredSBOM,
		RootPackages:     rootPackages,
		IncludedPackages: includedPackages,
		ExcludedPackages: excludedPackages,
		Statistics: FilteringStatistics{
			InputPackages:        len(allPackages),
			OutputPackages:       len(includedPackages),
			InputRelationships:   len(inputSBOM.Relationships),
			OutputRelationships:  len(filteredSBOM.Relationships),
			FilteringDuration:    time.Since(startTime),
			RootMatches:          len(rootPackages),
			TransitiveInclusions: len(includedPackages) - len(rootPackages),
		},
	}

	slog.Info("SBOM filtering completed successfully",
		"output_packages", result.Statistics.OutputPackages,
		"output_relationships", result.Statistics.OutputRelationships,
		"filtering_duration_ms", result.Statistics.FilteringDuration.Milliseconds())

	return result, nil
}

// findPackagesWithBuildrootFiles identifies packages that have files present in the buildroot.
// It uses Syft's file coordinate system to match buildroot files to package file locations.
func (e *FilteringEngine) findPackagesWithBuildrootFiles(
	packages *pkg.Collection,
	buildrootPaths []string) ([]pkg.Package, error) {

	buildrootSet := make(map[string]bool)
	for _, path := range buildrootPaths {
		buildrootSet[path] = true
	}

	var rootPackages []pkg.Package

	for _, p := range packages.Sorted() {
		// Check if any of the package's file locations match buildroot files
		hasBuildrootFile := false
		for _, location := range p.Locations.ToSlice() {
			// Use RealPath for matching since buildroot paths are normalized to real paths
			coord := location.Coordinates
			if buildrootSet[coord.RealPath] {
				hasBuildrootFile = true
				break
			}
		}

		if hasBuildrootFile {
			rootPackages = append(rootPackages, p)
			slog.Debug("Package matched to buildroot",
				"package_name", p.Name,
				"package_id", string(p.ID()),
				"package_type", string(p.Type),
				"location_count", len(p.Locations.ToSlice()))
		}
	}

	return rootPackages, nil
}

// resolveTransitiveDependencies performs transitive dependency resolution using Syft's relationship data.
// It uses depth-first search to find all packages reachable from the root packages through dependency relationships.
func (e *FilteringEngine) resolveTransitiveDependencies(
	inputSBOM *sbom.SBOM,
	rootPackages []pkg.Package) ([]pkg.Package, error) {

	visited := make(map[artifact.ID]bool)
	var allIncluded []pkg.Package

	packageMap := make(map[artifact.ID]pkg.Package)
	for _, p := range inputSBOM.Artifacts.Packages.Sorted() {
		packageMap[p.ID()] = p
	}

	for _, rootPkg := range rootPackages {
		if !visited[rootPkg.ID()] {
			transitivePackages := e.dfsTraversal(inputSBOM, rootPkg, packageMap, visited)
			allIncluded = append(allIncluded, transitivePackages...)
		}
	}

	slog.Debug("Transitive dependency resolution completed",
		"root_packages", len(rootPackages),
		"total_included", len(allIncluded))

	return allIncluded, nil
}

// dfsTraversal performs depth-first search traversal using Syft's relationship data.
// It follows dependency relationships to find all packages transitively reachable from the given package.
func (e *FilteringEngine) dfsTraversal(
	inputSBOM *sbom.SBOM,
	currentPkg pkg.Package,
	packageMap map[artifact.ID]pkg.Package,
	visited map[artifact.ID]bool) []pkg.Package {

	if visited[currentPkg.ID()] {
		return nil
	}

	visited[currentPkg.ID()] = true
	result := []pkg.Package{currentPkg}

	// Find all relationships where this package is the "from" side
	for _, rel := range inputSBOM.Relationships {
		if rel.From.ID() == currentPkg.ID() {
			if e.isDependencyRelationship(rel.Type) {
				// Follow dependency relationships for transitive resolution
				if targetPkg, exists := packageMap[rel.To.ID()]; exists {
					transitivePackages := e.dfsTraversal(inputSBOM, targetPkg, packageMap, visited)
					result = append(result, transitivePackages...)
				}
			}
		}
	}

	return result
}

// isDependencyRelationship checks if a relationship type represents a dependency.
// It identifies various types of dependency relationships that should be followed during traversal.
func (e *FilteringEngine) isDependencyRelationship(relType artifact.RelationshipType) bool {
	dependencyTypes := []artifact.RelationshipType{
		artifact.DependencyOfRelationship,
		artifact.ContainsRelationship,
	}

	for _, depType := range dependencyTypes {
		if relType == depType {
			return true
		}
	}
	return false
}

// createFilteredSBOM creates a new SBOM containing only the included packages and their relationships.
// It maintains Syft's SBOM structure while filtering out packages and relationships not in the inclusion set.
func (e *FilteringEngine) createFilteredSBOM(
	originalSBOM *sbom.SBOM,
	includedPackages []pkg.Package) (*sbom.SBOM, error) {

	includedSet := make(map[artifact.ID]bool)
	for _, p := range includedPackages {
		includedSet[p.ID()] = true
	}

	var filteredRelationships []artifact.Relationship
	for _, rel := range originalSBOM.Relationships {
		if includedSet[rel.From.ID()] && includedSet[rel.To.ID()] {
			filteredRelationships = append(filteredRelationships, rel)
		}
	}

	filteredPackages := pkg.NewCollection(includedPackages...)

	// Create new SBOM with filtered data but original metadata
	filteredSBOM := &sbom.SBOM{
		Source:        originalSBOM.Source,
		Artifacts:     sbom.Artifacts{Packages: filteredPackages},
		Relationships: filteredRelationships,
		Descriptor:    originalSBOM.Descriptor,
	}

	return filteredSBOM, nil
}

// validateFilteredSBOM performs integrity validation on the filtered SBOM.
// It ensures that all relationships reference existing packages and that the SBOM structure is valid.
func (e *FilteringEngine) validateFilteredSBOM(s *sbom.SBOM) error {
	// Allow empty SBOMs - this is a valid result when no packages match the buildroot
	if s.Artifacts.Packages.PackageCount() == 0 {
		return nil
	}

	// Validate that all relationships reference existing packages
	packageIDs := make(map[artifact.ID]bool)
	for _, p := range s.Artifacts.Packages.Sorted() {
		packageIDs[p.ID()] = true
	}

	for _, rel := range s.Relationships {
		if !packageIDs[rel.From.ID()] {
			return fmt.Errorf("relationship references non-existent package: %s", rel.From.ID())
		}
		if !packageIDs[rel.To.ID()] {
			return fmt.Errorf("relationship references non-existent package: %s", rel.To.ID())
		}
	}

	return nil
}

// getExcludedPackages identifies packages that were excluded from the filtering result.
// It compares the original package set with the included packages to determine exclusions.
func (e *FilteringEngine) getExcludedPackages(
	allPackages, includedPackages []pkg.Package) []pkg.Package {

	includedSet := make(map[artifact.ID]bool)
	for _, p := range includedPackages {
		includedSet[p.ID()] = true
	}

	var excludedPackages []pkg.Package
	for _, p := range allPackages {
		if !includedSet[p.ID()] {
			excludedPackages = append(excludedPackages, p)
		}
	}

	return excludedPackages
}

// SaveFilteredSBOM saves the filtered SBOM to a file using the specified format.
// It leverages the processor's format handling capabilities to maintain format compatibility.
func (e *FilteringEngine) SaveFilteredSBOM(
	result *FilteringResult,
	outputPath, format string) error {

	return e.processor.SaveSBOM(result.FilteredSBOM, outputPath, format)
}

// GetFilteringStatistics returns detailed statistics about the filtering operation.
// It provides insights into the filtering process including performance metrics and package counts.
func (e *FilteringEngine) GetFilteringStatistics(result *FilteringResult) FilteringStatistics {
	return result.Statistics
}

// LogFilteringSummary logs a comprehensive summary of the filtering operation.
// It provides detailed information about the filtering results for debugging and monitoring.
func (e *FilteringEngine) LogFilteringSummary(result *FilteringResult) {
	stats := result.Statistics

	slog.Info("SBOM filtering summary",
		"input_packages", stats.InputPackages,
		"output_packages", stats.OutputPackages,
		"packages_excluded", stats.InputPackages-stats.OutputPackages,
		"input_relationships", stats.InputRelationships,
		"output_relationships", stats.OutputRelationships,
		"relationships_excluded", stats.InputRelationships-stats.OutputRelationships,
		"root_matches", stats.RootMatches,
		"transitive_inclusions", stats.TransitiveInclusions,
		"filtering_duration_ms", stats.FilteringDuration.Milliseconds())

	// Log sample of root packages for debugging
	if len(result.RootPackages) > 0 {
		var rootNames []string
		for i, p := range result.RootPackages {
			if i >= 5 { // Limit to first 5 for readability
				rootNames = append(rootNames, "...")
				break
			}
			rootNames = append(rootNames, fmt.Sprintf("%s@%s", p.Name, p.Version))
		}
		slog.Debug("Root packages sample", "packages", strings.Join(rootNames, ", "))
	}
}
