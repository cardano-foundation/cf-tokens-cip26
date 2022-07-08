# <p align="center">Cardano Java Utility lib</p>

<div align="center">
  <p>Collection of utility functions that help you build on Cardano</p>
</div>

## Introduction

This library is a collections of several functions that we found useful when building applications on Cardano using the Java programming language. It's main focus is the implementation of the features and cryptographic functions required by [CIP-26](https://github.com/cardano-foundation/CIPs/tree/master/CIP-0026).

As the development continues the library will be extended. If you are looking for a more complete Java library with features like transaction serialization and transmission check out the excellent [Bloxbean Cardano Client Lib](https://github.com/bloxbean/cardano-client-lib)

## Getting started

### Integrate in your project

TODO provide a maven import command

### Example: Build and sign metadata

```Java
package org.cardanofoundation.metadata

// TODO provide a proper Java example
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
