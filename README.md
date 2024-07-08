# SLH-DSA
The SLH-DSA project implements the stateless-hash digital signing algorithm(standardizing fips 205, adopted on Sphincs-Plus algorithm) in pure Python.

This project offers those future:
1. :beers: Zero dependencies;
2. :label: 100% type hint for all the codes;
3. :white_check_mark: Extreme good 98% test coverage;
4. :bookmark: This project doesn't use any c-extension so it can be run in any version of Python or any kind of system.
5. :tada: More futures coming soon!


The functionality is extremely simple to use, as demonstrated by the following example:
```python
from slhdsa import KeyPair, shake_256f, PublicKey

kp = KeyPair.gen(shake_256f)  # generate the keypair
sig = kp.sign(b"Hello World!")  # sign the message
kp.verify(b"Hello World!", sig)  # -> True
kp.verify(b"Hello World!", b"I'm the hacker!") # -> False
kp.verify(b"hello world!", sig)  # -> False
sig = kp.sign(b"Hello World!", randomize = True)  # sign the message randomized
kp.verify(b"Hello World!", sig)  # -> True

digest = kp.pub.digest()  # generate the digest of the public key so that other device could verify the sign
pub = PublicKey.from_digest(digest)  # generate public key
pub.verify(b"Hello World!", sig)  # -> True
pub.verify(b"Hello World", sig)  # -> False
```

## Copyright

Copyright(c) Colinxu2020 2024 All Rights Reserved.

This software is licensed under GNU Lesser General Public License Version 3 or later(on your option).
