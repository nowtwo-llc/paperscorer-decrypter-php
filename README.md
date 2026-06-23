# paper-scorer/decrypter-php

PaperScorer Decrypter

This PHP package encrypts and decrypts the payloads exchanged with the PaperScorer engine.

- Package version: 1.2.0

## Requirements

- PHP 8.0.0 and later
- `openssl` PHP extension

## Installation & Usage
### Composer

This package can be easily installed using the following composer command:

`composer require paper-scorer/decrypter-php`

### Usage

Include and run the following code in your project:

```php
use PaperScorer\DecrypterPhp\Decrypter;

// Create a decrypter with the key provided by PaperScorer.
$decrypter = new Decrypter($decryptKey);

// Decrypt the encrypted callback payload (returns a JSON string).
$decryptedResponse = $decrypter
    ->setEncryptedContent($encryptedContent)
    ->decrypt();

// Produce a payload this library can read back.
$payload = $decrypter->encrypt($decryptedResponse);
```

## Encryption scheme

- **Cipher:** `AES-128-CBC` (via OpenSSL, with `OPENSSL_RAW_DATA`)
- **Key derivation:** `SHA-256(decryptKey + salt)`, truncated to 16 bytes (AES-128)
- **Payload format:** fixed-width base64 fields, concatenated with no separators:

  | Field      | Raw bytes | Base64 chars | Position |
  |------------|-----------|--------------|----------|
  | IV         | 16        | 24           | 0–23     |
  | Salt       | 21        | 28           | 24–51    |
  | Ciphertext | variable  | variable     | 52–end   |

  The offsets depend on these exact byte lengths (a 16-byte IV always encodes to
  24 base64 chars; a 21-byte salt to 28). A fresh random IV and salt are generated
  on every call to `encrypt()`, so the same plaintext yields a different payload each time.

> **Security note:** Key derivation is a single SHA-256 pass with no iteration
> count (not PBKDF2/scrypt/argon2). This is a deliberate constraint to stay
> compatible with the existing PaperScorer payload format — it is not suitable as
> a general-purpose password-based encryption scheme.

## Testing

```bash
vendor/bin/phpunit
```

## Contributing

We are always looking for updates to the package that will help the community. If you have an idea for an update, please create a pull request with your changes.

## Publishing

1. Update the CHANGELOG file
1. `git tag -a vX.X.X`
1. `git push --tags origin HEAD:main`
1. Log into [Packagist](https://packagist.org/packages/paper-scorer/decrypter-php) and click "Update"
