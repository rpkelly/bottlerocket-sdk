Feature: SBOM Merge Command
  As a software supply chain manager
  I want to merge multiple SBOM files into a single comprehensive SBOM
  So that I can consolidate package information while eliminating duplicates

  Background:
    Given the sbomtool is installed and available

  Scenario: Basic SBOM merge with SPDX format
    Given I have 2 SPDX SBOM files
    When I run merge command with SPDX files
    Then the command should succeed
    And the output file should be created
    And the merged SBOM should be in SPDX format

  Scenario: Basic SBOM merge with CycloneDX format
    Given I have 2 CycloneDX SBOM files
    When I run merge command with CycloneDX files
    Then the command should succeed
    And the output file should be created
    And the merged SBOM should be in CycloneDX format

  Scenario: CPE-based package deduplication
    Given I have 2 SBOM files with duplicate packages having same CPE
    When I run merge command with duplicate packages
    Then the command should succeed
    And the merged SBOM should contain only 1 instance of the duplicate package
    And the package should have merged metadata from both inputs

  Scenario: Fallback deduplication for packages without CPE
    Given I have 2 SBOM files with duplicate packages without CPE
    When I run merge command with non-CPE duplicates
    Then the command should succeed
    And the merged SBOM should deduplicate using name+version+type

  Scenario: Relationship preservation during merge
    Given I have SBOM files with dependency relationships
    When I run merge command with relationships
    Then the command should succeed
    And all dependency relationships should be preserved
    And relationship references should point to canonical package IDs

  Scenario: Merge statistics reporting
    Given I have 3 SBOM files with known package counts
    When I run merge command with statistics
    Then the command should succeed
    And the output should report merge statistics

  Scenario: Large SBOM performance
    Given I have large SBOM files with many packages
    When I run merge command with large files
    Then the command should complete within reasonable time
    And memory usage should remain reasonable

  Scenario: Metadata consolidation
    Given I have 2 SBOM files with same package having different metadata
    When I run merge command with metadata differences
    Then the command should succeed
    And the merged package should have consolidated metadata

  Scenario: Output file validation
    Given I have 2 valid SBOM files
    When I run merge command for validation
    Then the command should succeed
    And the output file should be valid JSON
    And the output file should pass SBOM format validation

  Scenario: Format mismatch error handling
    Given I have SBOM files in different formats
    When I run merge command with mixed format files
    Then the command should fail
    And the error message should indicate format mismatch

  Scenario: Invalid input file handling
    Given I have one valid SBOM file
    And I have one non-existent file
    When I run merge command with missing file
    Then the command should fail
    And the error message should indicate the missing file
    And no output file should be created

  Scenario: Debug logging during merge
    Given I have 2 SBOM files to merge
    When I run merge command with debug logging
    Then the command should succeed
    And debug logs should contain merge process messages

  Scenario: Filter with automatic deduplication
    Given I have an SBOM with duplicate packages
    And I have a buildroot directory
    When I run filter command with deduplication
    Then the command should succeed
    And the filtered SBOM should have deduplicated packages
    And the deduplication should use the same CPE-based logic as merge

  Scenario: Filter deduplication statistics
    Given I have an SBOM with known duplicates
    When I run filter command with deduplication statistics
    Then the command should succeed
    And the output should include deduplication statistics
    And the statistics should show packages before and after deduplication
