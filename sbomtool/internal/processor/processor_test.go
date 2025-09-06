package processor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBottlerocketSyftProcessor(t *testing.T) {
	// GIVEN: A request to create a new processor
	// WHEN: NewBottlerocketSyftProcessor is called
	// THEN: A properly configured processor should be returned

	processor := NewBottlerocketSyftProcessor()

	require.NotNil(t, processor)
	assert.NotNil(t, processor.formatDecoders)
	assert.NotNil(t, processor.formatEncoders)

	// Verify we have some decoders and encoders available
	assert.Greater(t, len(processor.formatDecoders), 0)
	assert.Greater(t, len(processor.formatEncoders), 0)
}

func TestGenerateComprehensiveSBOM(t *testing.T) {
	// GIVEN: A processor and a test directory
	// WHEN: GenerateComprehensiveSBOM is called
	// THEN: An SBOM should be generated successfully

	processor := NewBottlerocketSyftProcessor()
	testDir := t.TempDir()

	// Create a simple test file structure
	err := os.MkdirAll(filepath.Join(testDir, "usr", "bin"), 0755)
	require.NoError(t, err)

	testFile := filepath.Join(testDir, "usr", "bin", "test-app")
	err = os.WriteFile(testFile, []byte("#!/bin/bash\necho 'test'"), 0755)
	require.NoError(t, err)

	sbom, err := processor.GenerateComprehensiveSBOM(testDir)

	require.NoError(t, err)
	require.NotNil(t, sbom)
	assert.NotNil(t, sbom.Artifacts.Packages)
	assert.NotNil(t, sbom.Source)
}

func TestGenerateComprehensiveSBOM_InvalidDirectory(t *testing.T) {
	// GIVEN: A processor and an invalid directory path
	// WHEN: GenerateComprehensiveSBOM is called
	// THEN: An error should be returned

	processor := NewBottlerocketSyftProcessor()
	invalidDir := "/nonexistent/directory"

	sbom, err := processor.GenerateComprehensiveSBOM(invalidDir)

	assert.Error(t, err)
	assert.Nil(t, sbom)
	assert.Contains(t, err.Error(), "failed to create Syft source")
}

func TestLoadSBOM_NonexistentFile(t *testing.T) {
	// GIVEN: A processor and a nonexistent file path
	// WHEN: LoadSBOM is called
	// THEN: An error should be returned

	processor := NewBottlerocketSyftProcessor()
	nonexistentFile := "/nonexistent/file.json"

	sbom, format, err := processor.LoadSBOM(nonexistentFile)

	assert.Error(t, err)
	assert.Nil(t, sbom)
	assert.Empty(t, format)
	assert.Contains(t, err.Error(), "failed to open SBOM file")
}

func TestSaveSBOM_UnsupportedFormat(t *testing.T) {
	// GIVEN: A processor, an SBOM, and an unsupported format
	// WHEN: SaveSBOM is called
	// THEN: An error should be returned

	processor := NewBottlerocketSyftProcessor()
	testDir := t.TempDir()
	testFile := filepath.Join(testDir, "output.txt")

	// Create a minimal SBOM
	testSBOM := &sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name:    "test",
			Version: "1.0.0",
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	err := processor.SaveSBOM(testSBOM, testFile, "unsupported-format")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func TestSaveSBOM_InvalidPath(t *testing.T) {
	// GIVEN: A processor, an SBOM, and an invalid file path
	// WHEN: SaveSBOM is called
	// THEN: An error should be returned

	processor := NewBottlerocketSyftProcessor()
	invalidPath := "/nonexistent/directory/output.json"

	// Create a minimal SBOM
	testSBOM := &sbom.SBOM{
		Descriptor: sbom.Descriptor{
			Name:    "test",
			Version: "1.0.0",
		},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// Try to find a valid format
	var validFormat string
	if len(processor.formatEncoders) > 0 {
		validFormat = string(processor.formatEncoders[0].ID())
	} else {
		validFormat = "syft-json" // fallback
	}

	err := processor.SaveSBOM(testSBOM, invalidPath, validFormat)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write SBOM to file")
}

func TestGetRelationships(t *testing.T) {
	// GIVEN: A processor and an SBOM with relationships
	// WHEN: GetRelationships is called
	// THEN: The relationships should be returned

	processor := NewBottlerocketSyftProcessor()

	// Create a test SBOM with some relationships
	testSBOM := &sbom.SBOM{
		Relationships: []artifact.Relationship{}, // Empty for this test
	}

	relationships := processor.GetRelationships(testSBOM)

	require.NotNil(t, relationships)
	assert.Equal(t, 0, len(relationships))
}

func TestCountPackagesByType(t *testing.T) {
	// GIVEN: A processor and a package collection with various types
	// WHEN: countPackagesByType is called
	// THEN: Correct counts should be returned

	tests := []struct {
		name          string
		packages      []pkg.Package
		targetType    pkg.Type
		expectedCount int
	}{
		{
			name: "count go packages",
			packages: []pkg.Package{
				{
					Type: pkg.GoModulePkg,
					Name: "go-package-1",
				},
				{
					Type: pkg.GoModulePkg,
					Name: "go-package-2",
				},
				{
					Type: pkg.RustPkg,
					Name: "rust-package-1",
				},
			},
			targetType:    pkg.GoModulePkg,
			expectedCount: 2,
		},
		{
			name: "count rust packages",
			packages: []pkg.Package{
				{
					Type: pkg.GoModulePkg,
					Name: "go-package-1",
				},
				{
					Type: pkg.RustPkg,
					Name: "rust-package-1",
				},
				{
					Type: pkg.RustPkg,
					Name: "rust-package-2",
				},
			},
			targetType:    pkg.RustPkg,
			expectedCount: 2,
		},
		{
			name: "count nonexistent type",
			packages: []pkg.Package{
				{
					Type: pkg.GoModulePkg,
					Name: "go-package-1",
				},
			},
			targetType:    pkg.PythonPkg,
			expectedCount: 0,
		},
		{
			name:          "empty collection",
			packages:      []pkg.Package{},
			targetType:    pkg.GoModulePkg,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewBottlerocketSyftProcessor()
			catalog := pkg.NewCollection(tt.packages...)

			count := processor.countPackagesByType(catalog, tt.targetType)

			assert.Equal(t, tt.expectedCount, count)
		})
	}
}

func TestProcessorIntegration(t *testing.T) {
	// GIVEN: A processor and a realistic test scenario
	// WHEN: Multiple operations are performed in sequence
	// THEN: All operations should work together correctly

	processor := NewBottlerocketSyftProcessor()
	testDir := t.TempDir()

	// Create a more realistic directory structure
	dirs := []string{
		"usr/bin",
		"usr/lib",
		"etc",
	}
	for _, dir := range dirs {
		err := os.MkdirAll(filepath.Join(testDir, dir), 0755)
		require.NoError(t, err)
	}

	// Create test files
	files := map[string]string{
		"usr/bin/myapp":    "#!/bin/bash\necho 'myapp'",
		"usr/lib/mylib.so": "fake shared library",
		"etc/myapp.conf":   "config=value",
	}
	for file, content := range files {
		path := filepath.Join(testDir, file)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
	}

	// Generate SBOM
	generatedSBOM, err := processor.GenerateComprehensiveSBOM(testDir)
	require.NoError(t, err)
	require.NotNil(t, generatedSBOM)

	// Get relationships
	relationships := processor.GetRelationships(generatedSBOM)
	require.NotNil(t, relationships)

	// Verify SBOM structure
	assert.NotNil(t, generatedSBOM.Artifacts.Packages)
	assert.NotNil(t, generatedSBOM.Source)
}
