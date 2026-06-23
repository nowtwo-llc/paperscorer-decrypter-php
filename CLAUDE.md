# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PaperScorer Decrypter (PHP) — a zero-dependency PHP library for encrypting and decrypting payloads exchanged with the PaperScorer engine. Requires PHP >= 8.0 with the `openssl` extension.

## Development Commands

```bash
# Install dependencies (includes PHPUnit as a dev dependency)
composer install

# Run all tests
vendor/bin/phpunit

# Run a single test by method name
vendor/bin/phpunit --filter testDecryptReturnsExpectedPlaintext
```

## Architecture

The entire library is a single class: `src/Decrypter.php` in namespace `PaperScorer\DecrypterPhp`.

**Decryption protocol:**
- Input is a base64-encoded string with three concatenated segments:
  - Bytes 0–24: IV (base64-encoded, decodes to 16 bytes)
  - Bytes 24–52: Salt (base64-encoded, decodes to 21 bytes)
  - Bytes 52+: Ciphertext (base64-encoded)
- Key derivation: `substr(sha256(decryptKey + decodedSalt), 0, 16)` (shared `deriveKey()` helper)
- Cipher: AES-128-CBC via `openssl_decrypt` with `OPENSSL_RAW_DATA`
- Output: decrypted JSON string

**Encryption protocol (`encrypt()`):**
- Generates a fresh random 16-byte IV and 21-byte salt per call, so the same plaintext yields a different payload each time.
- Reuses the same key derivation and cipher, then concatenates `base64(IV) . base64(salt) . base64(ciphertext)` — the exact format `decrypt()` reads back.
- Segment lengths and offsets are defined as named class constants (`IV_BYTE_LENGTH`, `SALT_BASE64_END`, etc.).
