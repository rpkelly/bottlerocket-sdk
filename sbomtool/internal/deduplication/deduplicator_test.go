package deduplication

import (
	"testing"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeduplicator(t *testing.T) {
	// GIVEN: A deduplication configuration
	// WHEN: NewDeduplicator is called
	// THEN: A properly configured deduplicator should be returned

	config := DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		FallbackStrategy: "name_version_type",
		MetadataMerging:  true,
		PreserveSources:  true,
	}

	dedup := NewDeduplicator(config)

	assert.NotNil(t, dedup)
	assert.Equal(t, config, dedup.config)
}

func TestDeduplicatePackages_CPEBased(t *testing.T) {
	// GIVEN: Multiple packages with the same CPE
	// WHEN: DeduplicatePackages is called
	// THEN: Packages should be deduplicated using CPE as the key

	config := DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		MetadataMerging:  true,
	}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{
			Name:    "glibc",
			Version: "2.31",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:gnu:glibc:2.31:*", cpe.GeneratedSource),
			},
		},
		{
			Name:    "glibc",
			Version: "2.31",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:gnu:glibc:2.31:*", cpe.GeneratedSource),
			},
		},
	}

	// Set IDs on packages
	for i := range packages {
		packages[i].SetID()
	}

	result := dedup.DeduplicatePackages(packages)

	assert.Equal(t, 2, result.Statistics.InputPackages)
	assert.Equal(t, 1, result.Statistics.OutputPackages)
	assert.Equal(t, 1, result.Statistics.DeduplicatedCount)
	assert.Equal(t, 1, result.Statistics.CPEBasedMatches)
	assert.Equal(t, 0, result.Statistics.FallbackMatches)
	assert.Len(t, result.CanonicalPackages, 1)
	// Since both packages are identical, they have the same ID, so only one mapping entry
	assert.Len(t, result.IDMapping, 1)
}

func TestDeduplicatePackages_FallbackStrategy(t *testing.T) {
	// GIVEN: Multiple packages without CPE but same name+version+type
	// WHEN: DeduplicatePackages is called
	// THEN: Packages should be deduplicated using fallback strategy

	config := DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
		FallbackStrategy: "name_version_type",
		MetadataMerging:  true,
	}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{
			Name:    "mylib",
			Version: "1.0.0",
			Type:    pkg.GoModulePkg,
		},
		{
			Name:    "mylib",
			Version: "1.0.0",
			Type:    pkg.GoModulePkg,
		},
	}

	// Set IDs on packages
	for i := range packages {
		packages[i].SetID()
	}

	result := dedup.DeduplicatePackages(packages)

	assert.Equal(t, 2, result.Statistics.InputPackages)
	assert.Equal(t, 1, result.Statistics.OutputPackages)
	assert.Equal(t, 1, result.Statistics.DeduplicatedCount)
	assert.Equal(t, 0, result.Statistics.CPEBasedMatches)
	assert.Equal(t, 1, result.Statistics.FallbackMatches)
}

func TestDeduplicatePackages_MetadataMerging(t *testing.T) {
	// GIVEN: Duplicate packages with different metadata
	// WHEN: DeduplicatePackages is called with metadata merging enabled
	// THEN: Metadata should be merged from all duplicates

	config := DeduplicationConfig{
		PreferCPE:       true,
		MetadataMerging: true,
	}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{
			Name:    "openssl",
			Version: "1.1.1",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:openssl:openssl:1.1.1:*", cpe.GeneratedSource),
			},
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MIT"),
			),
		},
		{
			Name:    "openssl",
			Version: "1.1.1",
			Type:    pkg.RpmPkg,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:openssl:openssl:1.1.1:*", cpe.GeneratedSource),
			},
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("Apache-2.0"),
			),
		},
	}

	// Set IDs on packages
	for i := range packages {
		packages[i].SetID()
	}

	result := dedup.DeduplicatePackages(packages)

	require.Len(t, result.CanonicalPackages, 1)

	var canonical *pkg.Package
	for _, p := range result.CanonicalPackages {
		canonical = p
		break
	}

	assert.Len(t, canonical.Licenses.ToUnorderedSlice(), 2)
	licenseValues := make([]string, 0)
	for _, license := range canonical.Licenses.ToUnorderedSlice() {
		licenseValues = append(licenseValues, license.Value)
	}
	assert.Contains(t, licenseValues, "MIT")
	assert.Contains(t, licenseValues, "Apache-2.0")
}

func TestDeduplicatePackages_NoDeduplication(t *testing.T) {
	// GIVEN: Packages with different names/versions
	// WHEN: DeduplicatePackages is called
	// THEN: No deduplication should occur

	config := DeduplicationConfig{
		PreferCPE: true,
	}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{
			Name:    "package1",
			Version: "1.0.0",
			Type:    pkg.RpmPkg,
		},
		{
			Name:    "package2",
			Version: "2.0.0",
			Type:    pkg.RpmPkg,
		},
	}

	result := dedup.DeduplicatePackages(packages)

	assert.Equal(t, 2, result.Statistics.InputPackages)
	assert.Equal(t, 2, result.Statistics.OutputPackages)
	assert.Equal(t, 0, result.Statistics.DeduplicatedCount)
	assert.Len(t, result.CanonicalPackages, 2)
}

func TestUpdateRelationships(t *testing.T) {
	// GIVEN: Relationships with package IDs that need updating
	// WHEN: UpdateRelationships is called with ID mapping
	// THEN: Relationships should be updated and deduplicated

	config := DeduplicationConfig{}
	dedup := NewDeduplicator(config)

	// Create mock packages for relationships
	pkg1 := &pkg.Package{Name: "pkg1", Version: "1.0"}
	pkg2 := &pkg.Package{Name: "pkg2", Version: "1.0"}
	pkg3 := &pkg.Package{Name: "pkg3", Version: "1.0"}

	// Set IDs on packages
	pkg1.SetID()
	pkg2.SetID()
	pkg3.SetID()

	relationships := []artifact.Relationship{
		{
			From: pkg1,
			To:   pkg2,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkg1,
			To:   pkg3,
			Type: artifact.DependencyOfRelationship,
		},
	}

	idMapping := map[string]string{
		string(pkg1.ID()): "canonical1",
		string(pkg2.ID()): "canonical2",
	}

	updated := dedup.UpdateRelationships(relationships, idMapping)

	// The relationships should not be deduplicated since they have different To packages
	assert.Len(t, updated, 2)
}

func TestGenerateCanonicalKey_CPEPreferred(t *testing.T) {
	// GIVEN: A package with CPE and CPE preference enabled
	// WHEN: generateCanonicalKey is called
	// THEN: CPE should be used as the key

	config := DeduplicationConfig{
		PreferCPE:        true,
		CPENormalization: true,
	}
	dedup := NewDeduplicator(config)

	p := pkg.Package{
		Name:    "test",
		Version: "1.0",
		Type:    pkg.RpmPkg,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource),
		},
	}

	key := dedup.generateCanonicalKey(p)

	assert.Contains(t, key, "2.3:a:test:test:1.0:*")
	assert.NotContains(t, key, "fallback:")
}

func TestGenerateCanonicalKey_FallbackStrategy(t *testing.T) {
	// GIVEN: A package without CPE
	// WHEN: generateCanonicalKey is called
	// THEN: Fallback strategy should be used

	config := DeduplicationConfig{
		PreferCPE: true,
	}
	dedup := NewDeduplicator(config)

	p := pkg.Package{
		Name:    "test",
		Version: "1.0",
		Type:    pkg.RpmPkg,
	}

	key := dedup.generateCanonicalKey(p)

	assert.Contains(t, key, "fallback:")
	assert.Contains(t, key, "test")
	assert.Contains(t, key, "1.0")
	assert.Contains(t, key, string(pkg.RpmPkg))
}

func TestNormalizeCPE(t *testing.T) {
	// GIVEN: Various CPE formats
	// WHEN: normalizeCPE is called
	// THEN: CPEs should be normalized consistently

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard CPE",
			input:    "cpe:2.3:a:gnu:glibc:2.31:*",
			expected: "2.3:a:gnu:glibc:2.31:*",
		},
		{
			name:     "CPE without prefix",
			input:    "2.3:a:gnu:glibc:2.31:*",
			expected: "2.3:a:gnu:glibc:2.31:*",
		},
		{
			name:     "legacy CPE format",
			input:    "a:gnu:glibc:2.31",
			expected: "2.3:a:gnu:glibc:2.31",
		},
	}

	config := DeduplicationConfig{CPENormalization: true}
	dedup := NewDeduplicator(config)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dedup.normalizeCPE(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeCPE_Disabled(t *testing.T) {
	// GIVEN: CPE normalization disabled
	// WHEN: normalizeCPE is called
	// THEN: CPE should be returned unchanged

	config := DeduplicationConfig{CPENormalization: false}
	dedup := NewDeduplicator(config)

	input := "cpe:2.3:a:gnu:glibc:2.31:*"
	result := dedup.normalizeCPE(input)

	assert.Equal(t, input, result)
}

func TestCalculatePackageCompleteness(t *testing.T) {
	// GIVEN: Packages with different levels of metadata completeness
	// WHEN: calculatePackageCompleteness is called
	// THEN: Scores should reflect completeness levels

	config := DeduplicationConfig{}
	dedup := NewDeduplicator(config)

	tests := []struct {
		name     string
		pkg      pkg.Package
		expected int
	}{
		{
			name: "minimal package",
			pkg: pkg.Package{
				Name: "test",
			},
			expected: 0,
		},
		{
			name: "package with version",
			pkg: pkg.Package{
				Name:    "test",
				Version: "1.0",
			},
			expected: 5,
		},
		{
			name: "package with CPE",
			pkg: pkg.Package{
				Name: "test",
				CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource)},
			},
			expected: 3,
		},
		{
			name: "complete package",
			pkg: pkg.Package{
				Name:     "test",
				Version:  "1.0",
				CPEs:     []cpe.CPE{cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource)},
				Licenses: pkg.NewLicenseSet(pkg.NewLicense("MIT")),
			},
			expected: 9, // 5 (version) + 3 (CPE) + 1 (license)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := dedup.calculatePackageCompleteness(tt.pkg)
			assert.Equal(t, tt.expected, score)
		})
	}
}

func TestSelectCanonicalPackage(t *testing.T) {
	// GIVEN: Multiple packages with different completeness scores
	// WHEN: selectCanonicalPackage is called
	// THEN: The most complete package should be selected

	config := DeduplicationConfig{}
	dedup := NewDeduplicator(config)

	pkg1 := &pkg.Package{Name: "test"}
	pkg2 := &pkg.Package{
		Name:    "test",
		Version: "1.0",
		CPEs:    []cpe.CPE{cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource)},
	}
	pkg3 := &pkg.Package{Name: "test", Version: "1.0"}

	packages := []*pkg.Package{pkg1, pkg2, pkg3}

	canonical := dedup.selectCanonicalPackage(packages)

	assert.Equal(t, pkg2, canonical)
}

func TestDeduplicationStatistics(t *testing.T) {
	// GIVEN: A deduplication operation
	// WHEN: DeduplicatePackages completes
	// THEN: Statistics should be accurately recorded

	config := DeduplicationConfig{PreferCPE: true}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{Name: "pkg1", Version: "1.0", Type: pkg.RpmPkg},
		{Name: "pkg1", Version: "1.0", Type: pkg.RpmPkg},
		{Name: "pkg2", Version: "2.0", Type: pkg.RpmPkg},
	}

	// Set IDs on packages
	for i := range packages {
		packages[i].SetID()
	}

	startTime := time.Now()
	result := dedup.DeduplicatePackages(packages)
	endTime := time.Now()

	assert.Equal(t, 3, result.Statistics.InputPackages)
	assert.Equal(t, 2, result.Statistics.OutputPackages)
	assert.Equal(t, 1, result.Statistics.DeduplicatedCount)
	assert.True(t, result.Statistics.ProcessingTime > 0)
	assert.True(t, result.Statistics.ProcessingTime < endTime.Sub(startTime)+time.Millisecond)
}

func TestDeduplicationEvents(t *testing.T) {
	// GIVEN: Packages that will be deduplicated
	// WHEN: DeduplicatePackages is called
	// THEN: Deduplication events should be logged

	config := DeduplicationConfig{PreferCPE: true}
	dedup := NewDeduplicator(config)

	packages := []pkg.Package{
		{
			Name:    "test",
			Version: "1.0",
			Type:    pkg.RpmPkg,
			CPEs:    []cpe.CPE{cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource)},
		},
		{
			Name:    "test",
			Version: "1.0",
			Type:    pkg.RpmPkg,
			CPEs:    []cpe.CPE{cpe.Must("cpe:2.3:a:test:test:1.0:*", cpe.GeneratedSource)},
		},
	}

	// Set IDs on packages
	for i := range packages {
		packages[i].SetID()
	}

	result := dedup.DeduplicatePackages(packages)

	assert.Len(t, result.ProcessingLog, 1)

	event := result.ProcessingLog[0]
	assert.Equal(t, "cpe_match", event.Type)
	assert.Len(t, event.PackageIDs, 2)
	assert.Equal(t, "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*", event.CPE)
	assert.False(t, event.Timestamp.IsZero())
}
