# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0]

### Breaking Changes

- **Artifact Renamed**: Maven artifact ID changed from `core` to `cf-tokens-cip26`
- **Repository Renamed**: GitHub repository renamed from `cf-metadata-core` to `cf-tokens-cip26`
- **Java 21 Required**: Minimum Java version upgraded from 18 to 21
- **BouncyCastle Artifact Change**: Changed from `bcprov-jdk15on` to `bcprov-jdk18on` (required for Java 21)

### Added

- **Strongly-Typed API**: New `ValidationField` enum for type-safe property access
  - `addProperty(ValidationField.NAME, ...)` instead of `addProperty("name", ...)`
  - `validateProperty(ValidationField.NAME, ...)` for type-safe validation
  - `fromPropertyName()` and `toPropertyName()` helper methods
- **Logo Validation**: Added validation for logo property with max size of 87,400 characters per CIP-26
- **URL Validation**: Added validation for url property with max size of 250 characters
- **Convenience Constructor**: `MetadataProperty(T value)` constructor for simplified property creation
- **Null Object Pattern**: Field-level initialization for signatures list to prevent NPE
- **Enhanced Documentation**:
  - Added comprehensive API overview with code examples
  - Added CIP-26 specification table with property constraints
  - Added multi-build-tool support (Maven, Gradle, Gradle Kotlin DSL, SBT)
  - Improved quick start example with strongly-typed API

### Changed

- **Java 21 Upgrade**: Source and target compiler upgraded to Java 21
- **Dependency Updates** (all backward compatible):
  - Jackson: 2.13.2 → 2.17.2
  - Log4j: 2.17.2 → 2.23.1
  - BouncyCastle: 1.70 → 1.78.1
  - JUnit Jupiter: 5.8.2 → 5.10.3
  - AssertJ: 3.22.0 → 3.26.3
  - Mockito: 4.5.1 → 5.13.0
  - Hamcrest: 2.2 → 3.0
  - Lombok: 1.18.22 → 1.18.40
- **Maven Plugin Updates**:
  - Compiler Plugin: 3.10.0 → 3.13.0
  - Surefire Plugin: 3.0.0-M5 → 3.2.5
  - JaCoCo: 0.8.8 → 0.8.12 (Java 21 support)
  - Flatten Plugin: 1.2.7 → 1.6.0
  - PMD Plugin: 3.17.0 → 3.25.0
  - Javadoc Plugin: 3.4.1 → 3.10.1
  - Source Plugin: 3.2.1 → 3.3.1
  - Site Plugin: 4.0.0-M2 → 4.0.0-M13
  - Project Info Reports Plugin: 3.3.0 → 3.6.2
- **README Improvements**: Complete rewrite with better structure, examples, and clarity
- **GitHub Actions**: Updated CI/CD workflow to use Java 21

### Fixed

- Fixed typo in property version: `verison` → `version` (surefire and jacoco plugins)
- Fixed `addOrUpdateSignature()` with defensive null checks
- All 181 tests passing with Java 21 and updated dependencies

### Migration Guide

#### Artifact ID Change
Update your dependency declarations:

**Maven:**
```xml
<dependency>
    <groupId>org.cardanofoundation.metadatatools</groupId>
    <artifactId>cf-tokens-cip26</artifactId>  <!-- was: core -->
    <version>2.0.0-SNAPSHOT</version>
</dependency>
```

**Gradle:**
```groovy
implementation 'org.cardanofoundation.metadatatools:cf-tokens-cip26:2.0.0-SNAPSHOT'
```

#### Java Version
Ensure you're using Java 21 or higher:
```bash
java -version  # Should show 21+
```

#### API Migration (Optional)
While the old string-based API is still supported, consider migrating to the strongly-typed API:

**Before (still works):**
```java
metadata.addProperty("name", new MetadataProperty<>("Token Name", 0, null));
```

**After (recommended):**
```java
metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Token Name"));
```

## [1.1.0] - 2024-01-17

### Features

- Initial release with CIP-26 metadata support
- Key serialization and cryptographic operations
- Policy script handling

## [1.0.0] - 2024-01-16

### Features

- Initial implementation of CIP-26 compliant offchain metadata
- Metadata creation, signing, and validation
- Support for required properties (name, description)
- Support for optional properties (ticker, decimals, logo)
- Policy script integration
