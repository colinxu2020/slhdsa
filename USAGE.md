# `slh-dsa` Usage Guide

This project is a pure Python implementation of the SLH-DSA algorithm. This document introduces the usage of all public APIs.

**⚠️ Warning:**
Do not directly use the `slhdsa.lowlevel` submodules. Only use them directly if you absolutely know what you are doing.

## Imports & Parameter Selection

When generating keys, signing, and verifying, you need to specify a parameter set. This package directly exports all supported FIPS 205 parameter objects, including various security levels and optimization variants based on SHAKE and SHA2 (`s` stands for short signature size, `f` stands for fast signing speed).

Regarding the sizes and their corresponding security levels:
- **128** satisfies NIST's **Security Category 1**.
- **192** satisfies NIST's **Security Category 3**.
- **256** satisfies NIST's **Security Category 5**.

Available parameters:
- **SHAKE Series**: `shake_128s`, `shake_128f`, `shake_192s`, `shake_192f`, `shake_256s`, `shake_256f`
- **SHA2 Series**: `sha2_128s`, `sha2_128f`, `sha2_192s`, `sha2_192f`, `sha2_256s`, `sha2_256f`

```python
from slhdsa import KeyPair, PublicKey, SecretKey
from slhdsa import shake_128f, sha2_128s # Import the required parameters
```

## 1. KeyPair

`KeyPair` contains a public key (`PublicKey`) and a secret key (`SecretKey`). It is the most convenient way to generate and manage new keys.

### 1.1 Generate a New Key Pair
```python
# Generate a key pair using the specified parameters (e.g., shake_128f)
keypair = KeyPair.gen(shake_128f)
```

### 1.2 Export and Load Digest
You can export a `KeyPair` to a compact byte string format (a concatenation of the public and secret key raw bytes) and load it later:
```python
# Export key pair digest
digest = keypair.digest()

# Load key pair from digest
loaded_keypair = KeyPair.from_digest(digest, shake_128f)
```

### 1.3 Quick Access to Public/Secret Keys
```python
pub_key = keypair.pub  # Returns a PublicKey instance
sec_key = keypair.sec  # Returns a SecretKey instance
```

The `KeyPair` class also provides `.sign()`, `.sign_pure()`, `.sign_hash()`, and related verification methods as a convenient wrapper around the underlying public/secret key methods. For detailed mechanics, refer to the private and public key classes below.

---

## 2. SecretKey

Represents an SLH-DSA secret key, used to generate digital signatures.

### 2.1 Signing Methods

`SecretKey` provides three methods to generate signatures:

- **Pure Signature (`sign_pure`) - Recommended**
  ```python
  sig = sec_key.sign_pure(msg=b"hello")
  ```
  This is the recommended method that fully complies with the **final version of the FIPS 205 specification**. `ctx` is an optional context string, which must not exceed 255 bytes. `randomize` controls whether randomness is introduced into the signature.

- **Pre-hash Signature (`sign_hash`) - Recommended for large or streaming data**
  ```python
  sig = sec_key.sign_hash(msg=b"large data")
  ```
  This API is recommended when you need to sign large payloads or streaming data. It also fully complies with the FIPS 205 final specification. By default, it automatically determines the appropriate hash function for pre-hashing based on the security category of your selected parameter. You can also override this by passing a custom `prehash` function.

- **Bare Signature (`sign`) - Not Recommended**
  ```python
  sig = sec_key.sign(msg=b"hello")
  ```
  This method implements the SLH-DSA **Initial Draft** standard, rather than the final specification. While there are no security issues with this version, it may cause interoperability problems with other applications. It is not recommended for new applications.

### 2.2 Export and Load
- **Digest Format**:
  ```python
  # Export
  priv_digest = sec_key.digest()
  # Load
  sec_key = SecretKey.from_digest(priv_digest, shake_128f)
  ```
- **PKCS / PEM Format**:
  ```python
  # Save to PEM format file
  sec_key.to_pkcs("private.pem")
  # Load from PEM format file
  sec_key = SecretKey.from_pkcs("private.pem")
  ```

### 2.3 Derive Public Key or Key Pair
You can easily derive the corresponding public key or complete key pair from the secret key (this does not involve any high-overhead computations):
- `sec_key.pubkey`: Extracts the corresponding public key (`PublicKey` instance).
- `sec_key.keypair`: Extracts the corresponding key pair (`KeyPair` instance).

---

## 3. PublicKey

Represents an SLH-DSA public key, used to verify digital signatures.

### 3.1 Verification Methods

`PublicKey` provides three verification methods corresponding to the signing methods. They return `True` upon successful verification and `False` otherwise:

- **Pure Verification (`verify_pure`) - Recommended for general usage**
  ```python
  is_valid = pub_key.verify_pure(b"hello", sig)
  ```
- **Pre-hash Verification (`verify_hash`) - Recommended for large or streaming data**
  ```python
  is_valid = pub_key.verify_hash(b"large data", sig)
  ```
- **Bare Verification (`verify`) - Not Recommended for new application**
  ```python
  is_valid = pub_key.verify(msg=b"hello", sig=sig)
  ```

### 3.2 Export and Load
- **Raw Format**:
  ```python
  # Export
  pub_digest = pub_key.digest()
  # Load
  pub_key = PublicKey.from_digest(pub_digest, shake_128f)
  ```
- **PKCS / PEM Format**:
  ```python
  # Save to PEM format file
  pub_key.to_pkcs("public.pem")
  # Load from PEM format file
  pub_key = PublicKey.from_pkcs("public.pem")
  ```

---

## 4. Exceptions

The package provides exception classes to handle various runtime errors. All exceptions can be imported directly from `slhdsa`:

- `SLHDSAException`: Base class for all exceptions raised by this library.
- `SLHDSAKeyException`: Raised during key parsing or when an invalid key structure is encountered.
- `SLHDSASignException`: Raised when an issue occurs during the signing operation.
- `SLHDSAVerifyException`: Raised when an issue occurs during the verification operation. *(Note: Standard verification failures usually return `False` rather than raising an exception; an exception usually indicates that the input data structure is corrupted or an internal error occurred).*
