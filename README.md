# PySHA: A Python Cryptographic Hash Library

## Overview

PySHA is a pure Python implementation of three widely used cryptographic hash algorithms: SHA-1, SHA-256, and SHA-512. These algorithms are implemented from scratch, without relying on external libraries for the core hashing logic.

## Features

- Implements SHA-1, SHA-256, and SHA-512 according to their respective specifications:
  - **SHA-1 Specification**: FIPS PUB 180-1
  - **SHA-256 and SHA-512 Specifications**: FIPS PUB 180-4
- Pure Python implementation with no external dependencies for the core algorithms.
<!-- - Fully tested against known test vectors to ensure correctness. -->

## Getting Started

### Prerequisites

To use PySHA, you need:

- Python 3.6 or higher installed on your system.

### Installation

Clone the repository:

```bash
git clone https://github.com/rufilboss/PySHA.git
cd PySHA
```

## Usage

### Example: Compute a SHA-256 Hash

```python
from pysha import SHA256

data = b"hello world"
sha256 = SHA256()
print("SHA-256:", sha256.digest(data))
```

## Supported Hash Functions

- **SHA-1**: `SHA1.digest(data: bytes) -> str`
- **SHA-256**: `SHA256.digest(data: bytes) -> str`
- **SHA-512**: Working on this...

<!-- ## Testing
WILL WRITE THE TEST CASE LATER
The project includes comprehensive test cases using official test vectors from the specifications. To run the tests:

```bash
python -m unittest discover
``` -->

## Implementation Details

### SHA-1

- Operates on 512-bit blocks.
- Produces a 160-bit (20-byte) hash output.
- Based on a Merkle-Damgård construction using the Davies-Meyer compression function.

### SHA-256

- Operates on 512-bit blocks.
- Produces a 256-bit (32-byte) hash output.
- Utilizes 64 rounds of processing with a fixed set of constants and bitwise operations.

### SHA-512 (Planned)

- Operates on 1024-bit blocks.
- Produces a 512-bit (64-byte) hash output.
- Similar to SHA-256 but uses a larger word size (64 bits) and 80 rounds.

## Roadmap

- [x] Implement SHA-1
- [x] Implement SHA-256
- [ ] Implement SHA-512
- [ ] Add support for other SHA-2 variants (e.g., SHA-224, SHA-384)

## Contributing

Contributions are welcome! If you'd like to contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-xyz`).
3. Commit your changes (`git commit -m 'Add feature xyz'`).
4. Push to your fork (`git push origin feature-xyz`).
5. Open a pull request.

## Acknowledgements

- This project was inspired by [Truthixify](https://github.com/Truthixify/sha) and the concept was derived from [SHA specifications](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
<!-- - Test vectors from [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program). -->

---

**Happy hashing!**
