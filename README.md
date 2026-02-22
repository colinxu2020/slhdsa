# SLH-DSA

[![CI](https://github.com/colinxu2020/slhdsa/actions/workflows/ci.yml/badge.svg)](https://github.com/colinxu2020/slhdsa/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/colinxu2020/slhdsa/graph/badge.svg?token=OAQXHYD9TM)](https://codecov.io/github/colinxu2020/slhdsa)
![PyPI - Downloads](https://img.shields.io/pypi/dm/slh-dsa)
![GitHub License](https://img.shields.io/github/license/colinxu2020/slhdsa)

The SLH-DSA project is a pure Python implementation of the Stateless Hash-Based Digital Signature Algorithm, as specified in [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (derived from the SPHINCS+ algorithm).

## Features

This project offers the following features:
1. 🍻 **Zero dependencies!**
2. 🏷️ **100% type-hinted codebase!**
3. ✅ **100% test coverage!**
4. 🔖 **Supports modern Python versions!**
5. ⚒️ **Designed for humans!**
6. 🎉 **More features coming soon!**

## Installation

```bash
pip install slh-dsa
```

## Quick Start

The functionality is extremely simple to use, as demonstrated by the following example:

```python
from slhdsa import KeyPair, shake_256f, PublicKey

# Generate the keypair
kp = KeyPair.gen(shake_256f)

# Sign the message
sig = kp.sign(b"Hello World!")

# Verify the signature
kp.verify(b"Hello World!", sig)        # -> True
kp.verify(b"Hello World!", b"I'm the hacker!") # -> False
kp.verify(b"hello world!", sig)        # -> False

# Sign the message with randomization
sig = kp.sign(b"Hello World!", randomize=True)
kp.verify(b"Hello World!", sig)        # -> True

# Export the public key digest so other devices can verify the signature
digest = kp.pub.digest()

# Recover the public key from the digest
pub = PublicKey.from_digest(digest, shake_256f)
pub.verify(b"Hello World!", sig)       # -> True
pub.verify(b"Hello World", sig)        # -> False
```

## License & Copyright

Copyright (c) 2024-2025 Colinxu2020. All Rights Reserved.

This software is licensed under the **GNU Lesser General Public License Version 3** or later (at your option).
