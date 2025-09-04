package merge

import (
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestMerge(t *testing.T) {
	// GIVEN: Multiple SBOM files with overlapping packages
	// WHEN: Merge is called with valid configuration
	// THEN: SBOMs should be merged with proper deduplication

	tests := []struct {
		name          string
		config        MergeConfig
		inputFiles    []string
		expectedError bool
	}{
		{
			name: "insufficient input files",
			config: MergeConfig{
				OutputPath: filepath.Join(t.TempDir(), "merged.json"),
			},
			inputFiles:    []string{"single.json"},
			expectedError: true,
		},
		{
			name: "missing output path",
			config: MergeConfig{
				Level: 0,
			},
			inputFiles:    []string{"sbom1.json", "sbom2.json"},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Merge(tt.config, tt.inputFiles)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result.Statistics.ProcessingTime == 0 {
				t.Error("expected non-zero processing time")
			}
		})
	}
}

func TestValidateInputs(t *testing.T) {
	// GIVEN: Various input configurations
	// WHEN: validateInputs is called
	// THEN: Appropriate validation results should be returned

	tests := []struct {
		name        string
		config      MergeConfig
		inputFiles  []string
		expectError bool
	}{
		{
			name: "valid configuration",
			config: MergeConfig{
				OutputPath: "/tmp/output.json",
			},
			inputFiles:  []string{"file1.json", "file2.json"},
			expectError: false,
		},
		{
			name: "insufficient files",
			config: MergeConfig{
				OutputPath: "/tmp/output.json",
			},
			inputFiles:  []string{"single.json"},
			expectError: true,
		},
		{
			name:        "missing output path",
			config:      MergeConfig{},
			inputFiles:  []string{"file1.json", "file2.json"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInputs(tt.config, tt.inputFiles)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestMergeSBOMs(t *testing.T) {
	// GIVEN: Multiple SBOMs with packages and relationships
	// WHEN: mergeSBOMs is called
	// THEN: All packages and relationships should be collected

	sbom1 := createTestSBOM("test1", []pkg.Package{
		createTestPackage("pkg1", "1.0.0", "cpe:2.3:a:vendor:pkg1:1.0.0:*"),
		createTestPackage("pkg2", "2.0.0", ""),
	})

	sbom2 := createTestSBOM("test2", []pkg.Package{
		createTestPackage("pkg1", "1.0.0", "cpe:2.3:a:vendor:pkg1:1.0.0:*"), // Duplicate
		createTestPackage("pkg3", "3.0.0", ""),
	})

	sboms := []*sbom.SBOM{sbom1, sbom2}

	merged, packages, relationships := mergeSBOMs(sboms)

	if merged == nil {
		t.Fatal("expected merged SBOM, got nil")
	}

	if len(packages) != 4 {
		t.Errorf("expected 4 packages, got %d", len(packages))
	}

	if len(relationships) != 2 {
		t.Errorf("expected 2 relationships, got %d", len(relationships))
	}
}

func TestCreateFinalSBOM(t *testing.T) {
	// GIVEN: Base SBOM, canonical packages, and relationships
	// WHEN: createFinalSBOM is called
	// THEN: Final SBOM should be properly constructed

	base := &sbom.SBOM{
		Descriptor: sbom.Descriptor{Name: "test"},
	}

	canonicalPackages := map[string]*pkg.Package{
		"key1": createTestPackagePtr("pkg1", "1.0.0", ""),
		"key2": createTestPackagePtr("pkg2", "2.0.0", ""),
	}

	relationships := []artifact.Relationship{
		{
			From: pkg.Package{Name: "pkg1"},
			To:   pkg.Package{Name: "pkg2"},
			Type: artifact.DependencyOfRelationship,
		},
	}

	final := createFinalSBOM(base, canonicalPackages, relationships)

	if final.Descriptor.Name != "test" {
		t.Errorf("expected descriptor name 'test', got '%s'", final.Descriptor.Name)
	}

	if final.Artifacts.Packages.PackageCount() != 2 {
		t.Errorf("expected 2 packages, got %d", final.Artifacts.Packages.PackageCount())
	}

	if len(final.Relationships) != 1 {
		t.Errorf("expected 1 relationship, got %d", len(final.Relationships))
	}
}

// Helper functions for testing

func createTestSBOM(name string, packages []pkg.Package) *sbom.SBOM {
	collection := pkg.NewCollection()
	for _, p := range packages {
		collection.Add(p)
	}

	return &sbom.SBOM{
		Descriptor: sbom.Descriptor{Name: name},
		Source: source.Description{
			Name: name,
		},
		Artifacts: sbom.Artifacts{
			Packages: collection,
		},
		Relationships: []artifact.Relationship{
			{
				From: packages[0],
				To:   packages[len(packages)-1],
				Type: artifact.DependencyOfRelationship,
			},
		},
	}
}

func createTestPackage(name, version, cpeStr string) pkg.Package {
	p := pkg.Package{
		Name:    name,
		Version: version,
		Type:    pkg.RpmPkg,
		Locations: file.NewLocationSet(
			file.NewLocation("/test/path"),
		),
	}

	if cpeStr != "" {
		c, _ := cpe.New(cpeStr, cpe.GeneratedSource)
		p.CPEs = []cpe.CPE{c}
	}

	p.SetID()
	return p
}

func createTestPackagePtr(name, version, cpeStr string) *pkg.Package {
	p := createTestPackage(name, version, cpeStr)
	return &p
}
