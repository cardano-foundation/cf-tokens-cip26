[![License](https://img.shields.io/github/license/cardano-foundation/cf-tokens-cip68)](https://github.com/cardano-foundation/cf-tokens-cip68/blob/main/LICENSE)
![GitHub top language](https://img.shields.io/github/languages/top/cardano-foundation/cf-tokens-cip68)
[![Build](https://github.com/cardano-foundation/cf-tokens-cip68/actions/workflows/main.yaml/badge.svg)](https://github.com/cardano-foundation/cf-tokens-cip68/actions/workflows/main.yaml)
[![CodeQL](https://github.com/cardano-foundation/cf-tokens-cip68/actions/workflows/codeql.yaml/badge.svg)](https://github.com/cardano-foundation/cf-tokens-cip68/actions/workflows/codeql.yaml)
![coverage](https://github.com/cardano-foundation/cf-tokens-cip68/blob/badges/jacoco.svg)
![branches](https://github.com/cardano-foundation/cf-tokens-cip68/blob/badges/branches.svg)
[![Issues](https://img.shields.io/github/issues/cardano-foundation/cf-tokens-cip68)](https://github.com/cardano-foundation/cf-tokens-cip68/issues)

---

# CIP-26 Token Metadata Java Library

Utility library for building CIP-26 compliant token metadata on Cardano

## Introduction

This library provides utility classes and cryptographic functions for working with [CIP-26](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0026) token metadata on Cardano. CIP-26 defines an offchain metadata standard for Cardano native tokens with support for metadata signing and verification.

The library is specifically focused on CIP-26 metadata handling, validation, signing, and verification. If you are looking for a more complete Java library with features like transaction serialization and transmission check out the excellent [Bloxbean Cardano Client Lib](https://github.com/bloxbean/cardano-client-lib)

## Getting started

### Add to Your Project

The library is published to Maven Central and can be used with any JVM build tool.

#### Maven

```xml
<dependency>
    <groupId>org.cardanofoundation.metadatatools</groupId>
    <artifactId>cf-tokens-cip68</artifactId>
    <version>2.0.0</version>
</dependency>
```

#### Gradle

```groovy
implementation 'org.cardanofoundation.metadatatools:cf-tokens-cip68:2.0.0'
```

#### Gradle (Kotlin DSL)

```kotlin
implementation("org.cardanofoundation.metadatatools:cf-tokens-cip68:2.0.0")
```

#### SBT

```scala
libraryDependencies += "org.cardanofoundation.metadatatools" % "cf-tokens-cip68" % "2.0.0"
```

### Quick Start Example

This example demonstrates creating, signing, and validating CIP-26 compliant token metadata.

```java
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cardanofoundation.metadatatools.core.cip26.MetadataCreator;
import org.cardanofoundation.metadatatools.core.cip26.ValidationField;
import org.cardanofoundation.metadatatools.core.cip26.model.*;
import org.cardanofoundation.metadatatools.core.crypto.keys.Key;

// Configure Jackson ObjectMapper for JSON serialization
ObjectMapper objectMapper = new ObjectMapper();
objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

// Load signing key from Cardano key text envelope
KeyTextEnvelope signingKeyEnvelope = objectMapper.readValue("""
    {
        "type": "PaymentSigningKeyShelley_ed25519",
        "description": "Payment Signing Key",
        "cborHex": "58202b1b08bb20487b8dae9dac1445462d96fb9c4244e49e87b5d0785b9a2960a60b"
    }
    """, KeyTextEnvelope.class);
Key signingKey = Key.fromTextEnvelope(signingKeyEnvelope);

// Load policy script (used during token minting)
String policyJson = """
    {
        "type": "sig",
        "keyHash": "c04cc33b367f233e6ef0f15b05e2225b1974f4980611fb5852f6d01e"
    }""";
PolicyScript policyScript = objectMapper.readValue(policyJson, PolicyScript.class);

// Create metadata with properties using simplified constructor
Metadata metadata = new Metadata("TestToken", policyScript);
metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("Test Token"));
metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("A test token for demonstration"));
metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("TEST"));
metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(6));

// Sign the metadata
MetadataCreator.signMetadata(metadata, signingKey);

// Serialize to JSON
String metadataJson = objectMapper.writeValueAsString(metadata);
System.out.println("Metadata JSON: " + metadataJson);

// Deserialize from JSON
Metadata deserializedMetadata = objectMapper.readValue(metadataJson, Metadata.class);

// Load verification key
KeyTextEnvelope verificationKeyEnvelope = objectMapper.readValue("""
    {
        "type": "PaymentVerificationKeyShelley_ed25519",
        "description": "Payment Verification Key",
        "cborHex": "58208f26099728b91992ba5a06d8d91152ea6bd9aa1d944334fa96a4541b583c2634"
    }
    """, KeyTextEnvelope.class);
Key verificationKey = Key.fromTextEnvelope(verificationKeyEnvelope);

// Validate metadata with verification key
ValidationResult result = MetadataCreator.validateMetadata(deserializedMetadata, verificationKey);
if (result.isValid()) {
    System.out.println("✓ Metadata validation succeeded");
} else {
    System.out.println("✗ Metadata validation failed");
    result.getValidationErrors().forEach(error ->
        System.out.println("  - " + error.getField() + ": " + error.getMessage())
    );
}
```

## Build from Source

Clone the repository:

```bash
git clone git@github.com:cardano-foundation/cf-tokens-cip68.git
cd cf-tokens-cip68
```

Build with Maven:

```bash
mvn clean package
```

Run tests:

```bash
mvn test
```

## Requirements

- Java 18 or higher
- Maven 3.6+

## Features

### CIP-26 Token Metadata
- ✅ **Metadata Creation & Management**: Type-safe API for creating and managing token metadata
- ✅ **Property Validation**: Built-in validation for all CIP-26 properties (name, description, ticker, decimals, logo)
- ✅ **Cryptographic Signing**: Sign metadata with Ed25519 keys
- ✅ **Signature Verification**: Verify metadata authenticity with public keys
- ✅ **JSON Serialization**: Full Jackson support for JSON serialization/deserialization
- ✅ **Strongly-Typed API**: Use `ValidationField` enum for type-safe property access

### Cardano Cryptography
- ✅ **Multiple Key Formats**: Support for Cardano key text envelopes, bech32, and hex formats
- ✅ **Policy Scripts**: Parse and compute policy IDs from native scripts
- ✅ **CBOR Support**: Handle CBOR-encoded data structures

## API Overview

### Creating Metadata

```java
// Create metadata with required fields
Metadata metadata = new Metadata("MyToken");
metadata.addProperty(ValidationField.NAME, new MetadataProperty<>("My Token"));
metadata.addProperty(ValidationField.DESCRIPTION, new MetadataProperty<>("Token description"));

// Add optional fields
metadata.addProperty(ValidationField.TICKER, new MetadataProperty<>("MTK"));
metadata.addProperty(ValidationField.DECIMALS, new MetadataProperty<>(6));
metadata.addProperty(ValidationField.LOGO, new MetadataProperty<>("data:image/png;base64,..."));
```

### Validating Metadata

```java
// Validate metadata structure and properties
ValidationResult result = MetadataCreator.validateMetadata(metadata);

if (!result.isValid()) {
    result.getValidationErrors().forEach(error -> {
        System.out.println("Field: " + error.getField());
        System.out.println("Error: " + error.getMessage());
    });
}
```

### Signing Metadata

```java
// Sign all properties
MetadataCreator.signMetadata(metadata, signingKey);

// Sign specific property
MetadataCreator.signProperty(metadata, ValidationField.NAME, signingKey);
```

### Working with Keys

```java
// Load from text envelope
Key key = Key.fromTextEnvelope(keyEnvelope);

// Load from bech32
Key key = Key.fromBech32("addr_vk1...");

// Load from hex
Key key = Key.fromHex("5820...");
```

## CIP-26 Specification

This library implements [CIP-26: Cardano Off-Chain Metadata](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0026), which defines:

- Standard metadata properties for native tokens
- Cryptographic signing and verification mechanisms
- Subject-based identification for token metadata
- Validation rules for metadata properties

### Supported Properties

| Property | Type | Required | Max Length | Description |
|----------|------|----------|------------|-------------|
| `name` | String | ✅ Yes | 50 | Token display name |
| `description` | String | ✅ Yes | 500 | Token description |
| `ticker` | String | ❌ No | 2-9 | Short token symbol |
| `decimals` | Integer | ❌ No | ≥ 0 | Number of decimal places |
| `logo` | String | ❌ No | 87,400 | Base64-encoded image |

## Contributing

We welcome contributions! Here's how you can help:

- 🐛 **Report bugs**: [Open an issue](https://github.com/cardano-foundation/cf-tokens-cip68/issues/new) with a clear description
- 💡 **Suggest features**: Share your ideas in [Discussions](https://github.com/cardano-foundation/cf-tokens-cip68/discussions)
- 📖 **Improve documentation**: Help us make the docs better
- 🔧 **Submit pull requests**: Fix bugs or add features

Please read our [Contributing Guidelines](./CONTRIBUTING.md) and [Code of Conduct](./CODE-OF-CONDUCT.md) before contributing.

### Development Setup

```bash
# Clone the repository
git clone git@github.com:cardano-foundation/cf-tokens-cip68.git
cd cf-tokens-cip68

# Build and run tests
mvn clean install

# Run tests with coverage
mvn clean test jacoco:report
```

## License

This project is licensed under the **Mozilla Public License 2.0** (MPL-2.0). See [LICENSE](./LICENSE) for details.

## Support

- 📚 [Wiki Documentation](https://github.com/cardano-foundation/cf-tokens-cip68/wiki)
- 💬 [GitHub Discussions](https://github.com/cardano-foundation/cf-tokens-cip68/discussions)
- 🐛 [Issue Tracker](https://github.com/cardano-foundation/cf-tokens-cip68/issues)
- 📮 [Cardano StackExchange](https://cardano.stackexchange.com/) (use tag `cip26`)

## Acknowledgments

Built with ❤️ by the [Cardano Foundation](https://cardanofoundation.org/)

---

**Note**: This library focuses on CIP-26 metadata utilities. For full Cardano transaction capabilities, check out [Bloxbean Cardano Client Lib](https://github.com/bloxbean/cardano-client-lib).
