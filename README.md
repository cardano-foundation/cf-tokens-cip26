# <p align="center">Cardano Java Utility lib</p>

<div align="center">
  <p>Collection of utility functions that help you build on Cardano</p>
</div>

## Introduction

This library is a collections of several functions that we found useful when building applications on Cardano using the Java programming language. It's main focus is the implementation of the features and cryptographic functions required by [CIP-26](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0026).

As the development continues the library will be extended. If you are looking for a more complete Java library with features like transaction serialization and transmission check out the excellent [Bloxbean Cardano Client Lib](https://github.com/bloxbean/cardano-client-lib)

## Getting started

### Integrate in your project

At the moment only the snapshot version is served out via GitHub packages. This will for sure soon change but at the moment you need some additional configuration for Maven to access the prebuilt Snapshot package.

Create or modify your Maven `settings.xml` file (most likely located in your user folder in a folder called `.m2`). The file must contain an additional repository which points to the our GitHub repository and you must have a personal access token (PAT) created within your GitHub profile settings in order to access the repository.
```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
    <activeProfiles>
        <activeProfile>github</activeProfile>
    </activeProfiles>

    <profiles>
        <profile>
            <id>github</id>
            <repositories>
                <repository>
                    <id>central</id>
                    <url>https://repo1.maven.org/maven2/</url>
                </repository>
                <repository>
                    <id>github</id>
                    <url>https://maven.pkg.github.com/cardano-foundation/cf-metadata-core</url>
                    <snapshots>
                        <enabled>true</enabled>
                    </snapshots>
                </repository>
            </repositories>
        </profile>
    </profiles>

    <servers>
        <server>
            <id>github</id>
            <username>your_github_username_goes_here</username>
            <password>your_personal_access_token_goes_here</password>
        </server>
    </servers>
</settings>
```

Alternatively you can reference the GitHub packages repository directly within your `pom.xml` file but it is not advisable to store your PAT in there and maybe accidentally commit it with your other changes:
```xml
<repositories>
        <repository>
            <id>central</id>
            <url>https://repo1.maven.org/maven2/</url>
        </repository>
        <repository>
            <id>github</id>
            <url>https://maven.pkg.github.com/cardano-foundation/cf-metadata-core</url>
            <snapshots>
                <enabled>true</enabled>
            </snapshots>
        </repository>
    </repositories>
```

You can now reference the the dependency to the lib in your `pom.xml` with following snippet:
```xml
...
<dependency>
    <groupId>org.cardanofoundation.metadatatools</groupId>
    <artifactId>core</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
...
```

### Example: Build and sign metadata

```java
// This Jackson ObjectMapper instance is used for JSON de/serialization.
final ObjectMapper objectMapper = new ObjectMapper();
objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

// Step 1: Load the signing key from a Cardano json envelope representation containing the key material of the
// signing key encoded as CBOR represented as a hex string. We load the key from a String but nothing prevents
// us from loading it from a file directly.
final KeyTextEnvelope signingKeyEnvelope = objectMapper.readValue("""
        {
            "type": "PaymentSigningKeyShelley_ed25519",
            "description": "Payment Signing Key",
            "cborHex": "58202b1b08bb20487b8dae9dac1445462d96fb9c4244e49e87b5d0785b9a2960a60b"
        }
        """, KeyTextEnvelope.class);
final Key signingKey = Key.fromTextEnvelope(signingKeyEnvelope);

// Step 2: Load the monetary policy script used within the token minting operation. We load it from a String.
// Usually this will be loaded from the same file containing the policy that was used during the minting.
final String policyJson = """
        {
            "type": "atLeast",
            "required": 2,
            "scripts":
            [
            {
                "type": "before",
                "slot": 600
            },
            {
                "type": "sig",
                "keyHash": "c04cc33b367f233e6ef0f15b05e2225b1974f4980611fb5852f6d01e"
            },
            {
                "type": "after",
                "slot": 500
            }
            ]
        }""";
final PolicyScript policyScript = objectMapper.readValue(policyJson, PolicyScript.class);

// Step 3: Create the actual metadata providing some properties.
final TokenMetadata tokenMetadata = new TokenMetadata("CfTestCoin", policyScript, Map.ofEntries(
        entry("name", new TokenMetadataProperty<>("CfTestCoin", 0, null)),
        entry("description", new TokenMetadataProperty<>("We test with CfTestCoin.", 0, null)),
        entry("ticker", new TokenMetadataProperty<>("CfTstCn", 0, null)),
        entry("decimals", new TokenMetadataProperty<>(6, 0, null))
));

// Step 4: Sign the metadata with the signing key.
TokenMetadataCreator.signTokenMetadata(tokenMetadata, signingKey);

// Actually the example is over but usually you want to serialize your metadata to JSON or load metadata from
// JSON and perform a validation based on a certain verification key or likewise. The next steps are about those
// things.

// Step 5: Serialize the metadata to its string representation.
final String tokenMetadataAsJson = objectMapper.writeValueAsString(tokenMetadata);

// Step 6: Deserialize the metadata from its string representation.
final TokenMetadata tokenMetadataDeserialized = objectMapper.readValue(tokenMetadataAsJson, TokenMetadata.class);

// Step 7: Load the verification key
final KeyTextEnvelope verificationKeyEnvelope = objectMapper.readValue("""
        {
            "type": "PaymentVerificationKeyShelley_ed25519",
            "description": "Payment Verification Key",
            "cborHex": "58208f26099728b91992ba5a06d8d91152ea6bd9aa1d944334fa96a4541b583c2634"
        }
        """, KeyTextEnvelope.class);
final Key verificationKey = Key.fromTextEnvelope(verificationKeyEnvelope);

// Step 8: Try to validate the metadata given a verification key that must be included in the signatures.
log.info((TokenMetadataCreator.validateTokenMetadata(tokenMetadataDeserialized, verificationKey).isValid())
        ? "verification succeeded"
        : "verification failed");
```

### Build from source
Just clone the repo and use maven to build:

```sh
mvn package
```

## Features

Offchain metadata related:
- [x] Support of various key serialization formats used by Cardano
- [x] Serialization of CIP-26 compliant offchain metadata format
- [x] Signing of CIP-26 compliant offchain metadata

Later:
- [ ] peer-2-peer networking protocol for decentralized CIP-26 registry implementation

## Contributing

File an issue or a PR or reach out directly to us if you want to contribute.

When contributing to this project and interacting with others, please follow our [Contributing Guidelines](./CONTRIBUTING.md) and [Code of Conduct](./CODE-OF-CONDUCT.md).

---

<p align="center">
Thanks for visiting and enjoy :heart:!
</p>
