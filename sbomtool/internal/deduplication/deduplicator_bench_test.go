package deduplication

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

// BenchmarkDeduplicatePackages_Small benchmarks deduplication with small package sets
func BenchmarkDeduplicatePackages_Small(b *testing.B) {
	packages := createBenchmarkPackages(100, 0.2) // 100 packages, 20% duplicates
	dedup := NewDeduplicator(DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		FallbackStrategy: "name_version_type",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dedup.DeduplicatePackages(packages)
	}
}

// BenchmarkDeduplicatePackages_Medium benchmarks deduplication with medium package sets
func BenchmarkDeduplicatePackages_Medium(b *testing.B) {
	packages := createBenchmarkPackages(1000, 0.3) // 1000 packages, 30% duplicates
	dedup := NewDeduplicator(DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		FallbackStrategy: "name_version_type",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dedup.DeduplicatePackages(packages)
	}
}

// BenchmarkDeduplicatePackages_Large benchmarks deduplication with large package sets
func BenchmarkDeduplicatePackages_Large(b *testing.B) {
	packages := createBenchmarkPackages(10000, 0.4) // 10000 packages, 40% duplicates
	dedup := NewDeduplicator(DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		FallbackStrategy: "name_version_type",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dedup.DeduplicatePackages(packages)
	}
}

// BenchmarkUpdateRelationships benchmarks relationship updates
func BenchmarkUpdateRelationships(b *testing.B) {
	relationships := createBenchmarkRelationships(1000)
	idMapping := createBenchmarkIDMapping(500)
	dedup := NewDeduplicator(DeduplicationConfig{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dedup.UpdateRelationships(relationships, idMapping)
	}
}

// createBenchmarkPackages creates a set of packages for benchmarking
func createBenchmarkPackages(count int, duplicateRatio float64) []pkg.Package {
	packages := make([]pkg.Package, count)
	duplicateCount := int(float64(count) * duplicateRatio)

	// Create unique packages
	for i := 0; i < count-duplicateCount; i++ {
		packages[i] = pkg.Package{
			Name:    fmt.Sprintf("package-%d", i),
			Version: "1.0.0",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must(fmt.Sprintf("cpe:2.3:a:vendor:package-%d:1.0.0:*:*:*:*:*:*:*", i), ""),
			},
		}
	}

	// Create duplicate packages (same CPE, different metadata)
	for i := count - duplicateCount; i < count; i++ {
		originalIndex := i % (count - duplicateCount)
		packages[i] = pkg.Package{
			Name:    fmt.Sprintf("package-%d", originalIndex),
			Version: "1.0.0",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must(fmt.Sprintf("cpe:2.3:a:vendor:package-%d:1.0.0:*:*:*:*:*:*:*", originalIndex), ""),
			},
		}
	}

	return packages
}

// createBenchmarkRelationships creates relationships for benchmarking
func createBenchmarkRelationships(count int) []artifact.Relationship {
	relationships := make([]artifact.Relationship, count)
	for i := 0; i < count; i++ {
		fromPkg := pkg.Package{Name: fmt.Sprintf("from-%d", i)}
		toPkg := pkg.Package{Name: fmt.Sprintf("to-%d", i)}
		relationships[i] = artifact.Relationship{
			From: fromPkg,
			To:   toPkg,
			Type: artifact.DependencyOfRelationship,
		}
	}
	return relationships
}

// createBenchmarkIDMapping creates ID mappings for benchmarking
func createBenchmarkIDMapping(count int) map[string]string {
	mapping := make(map[string]string, count)
	for i := 0; i < count; i++ {
		mapping[fmt.Sprintf("old-id-%d", i)] = fmt.Sprintf("new-id-%d", i%100)
	}
	return mapping
}
