# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Cardano Foundation Metadata Core** library, a Java utility library for building on Cardano. The primary focus is implementing features and cryptographic functions required by **CIP-26** (Cardano Improvement Proposal 26) for offchain metadata handling.

CIP-26 defines how metadata for native tokens should be structured, signed, and verified in a decentralized manner. This library provides the tools to create, sign, validate, and manage this metadata.

## Development Environment

### Java Version
- **Java 18** is required
- Use SDKman to manage Java versions: `sdk use java 18.0.2-amzn`

### Build Tool
- Maven (multi-module project)
- Parent POM: `org.cardanofoundation.metadatatools:core-base`
- Main module: `core`

## Common Commands

### Build
```bash
# Build entire project
mvn package

# Clean build
mvn clean package

# Build without tests
mvn package -DskipTests
```

### Testing
```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=MetadataCreatorTest

# Run specific test method
mvn test -Dtest=MetadataCreatorTest#shouldSignAllPropertiesInMetadata

# Generate code coverage report (JaCoCo)
mvn test jacoco:report
# Report location: core/target/site/jacoco/index.html
```

### Code Quality
```bash
# Run PMD static analysis
mvn pmd:pmd

# Check for duplicated code
mvn pmd:cpd
```

## Architecture

### Package Structure

The codebase is organized into two main packages:

#### 1. `org.cardanofoundation.metadatatools.core.cip26`
Contains CIP-26 specific implementation for metadata handling:

- **`Metadata`**: Core data model representing token metadata with properties (name, description, ticker, decimals, logo, etc.)
- **`MetadataProperty<T>`**: Generic property container holding a value, sequence number, and attestation signatures
- **`MetadataCreator`**: Main API for creating, signing, and validating metadata
- **`MetadataValidationRules`**: Validation logic for metadata properties with specific constraints
- **`ValidationResult`**: Container for validation errors
- **`AttestationSignature`**: Represents Ed25519 signatures on metadata properties
- **`PolicyScript`**: Represents Cardano monetary policy scripts used in token minting
- **`KeyTextEnvelope`**: JSON envelope format for Cardano key serialization

#### 2. `org.cardanofoundation.metadatatools.core.crypto`
Cryptographic utilities:

- **`Key`**: Handles Ed25519 key operations (signing, verification, key derivation)
- **`KeyType`**: Enum for different Cardano key types (payment, policy, stake)
- **`Hashing`**: BLAKE2b-256 hashing utilities
- **`Bech32`**: Bech32 encoding/decoding for Cardano addresses

### Core Workflow

1. **Metadata Creation**: Create `Metadata` object with subject (policyId + assetName) and properties
2. **Property Addition**: Add properties like name, description, ticker, decimals to metadata
3. **Signing**: Use `MetadataCreator.signMetadata()` with Ed25519 signing key to create attestation signatures
4. **Validation**: Use `MetadataCreator.validateMetadata()` to verify:
   - Property constraints (e.g., name ≤ 50 chars, description ≤ 500 chars)
   - Required properties (name and description are mandatory)
   - Subject format (56-120 hex characters)
   - Signature authenticity (if verification key provided)
5. **Updates**: Use `MetadataCreator.validateMetadataUpdate()` to ensure sequence numbers increase

### Validation Rules

Key constraints enforced by `MetadataValidationRules`:

- **Subject**: 56-120 hex characters (28-byte policy ID + up to 32-byte asset name)
- **Name**: Required, max 50 characters
- **Description**: Required, max 500 characters
- **Ticker**: Optional, 2-9 characters
- **Decimals**: Optional, non-negative integer
- **Logo/URL**: No specific length constraints

### Key Concepts

**Subject**: The unique identifier for a token, composed of:
- Policy ID (56 hex chars = 28 bytes)
- Asset name (0-64 hex chars = 0-32 bytes)

**Sequence Numbers**: Properties have sequence numbers to track updates. When updating metadata, sequence numbers must increase to prevent rollback attacks.

**Attestation Signatures**: Each property can have multiple Ed25519 signatures from different keys, allowing multi-party attestation of metadata.

## Testing Strategy

### Test Structure
Tests use **JUnit 5** with **nested test classes** and **AssertJ** assertions for readability:

```java
@Nested
@DisplayName("Feature Category")
class FeatureTests {

    @Nested
    @DisplayName("Positive Tests")
    class PositiveTests { }

    @Nested
    @DisplayName("Negative Tests")
    class NegativeTests { }
}
```

### Key Test Files
- **`MetadataValidationTest`**: Tests for validation rules and constraints
- **`MetadataCreatorTest`**: Tests for metadata creation, signing, and validation workflows
- **`KeySerializationTests`**: Tests for key format conversions
- **`MetadataTests`**: Integration tests for complete workflows

### Test Resources
Test keys and policy scripts are in `core/src/test/resources/`:
- `policy.skey`: Ed25519 signing key
- `policy.script`: Sample policy script
- `payment.skey`: Alternative signing key for multi-key tests

## Dependencies

Key external dependencies:
- **Bouncy Castle** (`bcprov-jdk15on`): Ed25519 cryptography
- **Jackson** (`jackson-dataformat-cbor`): CBOR and JSON serialization
- **Lombok**: Boilerplate reduction
- **Log4j2**: Logging

## Important Notes

### Null Safety
After recent updates, validation rules handle null property values gracefully. When adding new validation logic, always check for null before calling methods on property values.

### Signature Handling
When iterating over signatures in metadata properties, always check if the signature list is null or empty first:
```java
if (entry.getValue().getSignatures() != null && !entry.getValue().getSignatures().isEmpty()) {
    // Process signatures
}
```

### CIP-26 Compliance
All metadata operations must comply with CIP-26 specification. When making changes to validation or serialization, verify against the CIP-26 standard.

## Build Profiles

### CI/CD Profile
The `ci-cd` profile is used for releases and includes GPG signing:
```bash
mvn clean package -P ci-cd
```

## Publishing

The project publishes to:
- Snapshots: https://s01.oss.sonatype.org/content/repositories/snapshots
- Releases: https://s01.oss.sonatype.org/service/local/staging/deploy/maven2
