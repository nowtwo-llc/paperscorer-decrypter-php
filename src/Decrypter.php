<?php

declare(strict_types=1);

/**
 * PaperScorer Decrypter - PHP Version
 *
 * @package PaperScorer
 * @author  PaperScorer Team
 */

namespace PaperScorer\DecrypterPhp;

use InvalidArgumentException;
use RuntimeException;

/**
 * Encrypts and decrypts payloads exchanged with the PaperScorer engine.
 *
 * The encrypted content is a base64-encoded string composed of three
 * concatenated, fixed-width segments:
 *   - Bytes  0–24:  IV (base64-encoded, decodes to 16 bytes)
 *   - Bytes 24–52:  Salt (base64-encoded, decodes to 21 bytes)
 *   - Bytes 52+:    Ciphertext (base64-encoded)
 *
 * Key derivation: SHA-256(decryptKey + decodedSalt), truncated to 16 bytes.
 * Cipher: AES-128-CBC with OPENSSL_RAW_DATA.
 *
 * @package PaperScorer
 * @author  PaperScorer Team
 */
class Decrypter
{
    /** Symmetric cipher used for both encryption and decryption. */
    private const CIPHER_ALGORITHM = 'AES-128-CBC';

    /** Hash algorithm used to derive the AES key from the key + salt. */
    private const HASH_ALGORITHM = 'sha256';

    // The payload uses fixed-width base64 fields because the raw byte lengths are
    // fixed: a 16-byte IV always encodes to 24 base64 chars, and a 21-byte salt
    // always encodes to 28. Changing either byte length would shift these offsets.
    private const IV_BYTE_LENGTH = 16;
    private const SALT_BYTE_LENGTH = 21;
    private const IV_BASE64_LENGTH = 24;
    private const SALT_BASE64_LENGTH = 28;
    private const SALT_BASE64_END = self::IV_BASE64_LENGTH + self::SALT_BASE64_LENGTH;
    private const AES_KEY_LENGTH = 16;

    /** @var string The key provided by PaperScorer (used for encrypt and decrypt) */
    protected string $decryptKey;

    /** @var string|null The encrypted payload to decrypt */
    protected ?string $encryptedContent = null;

    /**
     * @param string $decryptKey The decryption key provided by PaperScorer
     *
     * @throws InvalidArgumentException If the decryption key is empty
     */
    public function __construct(string $decryptKey)
    {
        if ($decryptKey === '') {
            throw new InvalidArgumentException(
                'Missing the required parameter $decryptKey when creating a new Decrypter object.'
            );
        }

        $this->setDecryptKey($decryptKey);
    }

    /**
     * Decrypt and return the encrypted content as a string.
     *
     * @return string The decrypted content (typically JSON)
     *
     * @throws RuntimeException If encrypted content has not been set
     * @throws InvalidArgumentException If the payload is too short to contain an IV and salt
     * @throws RuntimeException If decryption fails
     */
    public function decrypt(): string
    {
        if ($this->encryptedContent === null) {
            throw new RuntimeException(
                'Encrypted content must be set before calling decrypt().'
            );
        }

        if (strlen($this->encryptedContent) <= self::SALT_BASE64_END) {
            throw new InvalidArgumentException(
                'Encrypted content is too short. Expected more than ' . self::SALT_BASE64_END . ' characters.'
            );
        }

        // Extract the three base64-encoded segments from the payload
        $ivBase64 = substr($this->encryptedContent, 0, self::IV_BASE64_LENGTH);
        $saltBase64 = substr($this->encryptedContent, self::IV_BASE64_LENGTH, self::SALT_BASE64_LENGTH);
        $cipherTextBase64 = substr($this->encryptedContent, self::SALT_BASE64_END);

        // Derive a 16-byte AES key from the decrypt key and the decoded salt
        $secretKey = $this->deriveKey(base64_decode($saltBase64));

        $decryptedContent = openssl_decrypt(
            base64_decode($cipherTextBase64),
            self::CIPHER_ALGORITHM,
            $secretKey,
            OPENSSL_RAW_DATA,
            base64_decode($ivBase64)
        );

        if ($decryptedContent === false) {
            throw new RuntimeException(
                'Decryption failed. Verify that the decrypt key and encrypted content are correct.'
            );
        }

        return $decryptedContent;
    }

    /**
     * Encrypt plaintext into a payload that {@see decrypt()} can read back.
     *
     * A fresh random IV and salt are generated on every call, so encrypting the
     * same plaintext twice yields different payloads.
     *
     * @param string $plaintext The text to encrypt (typically JSON)
     *
     * @return string The encrypted payload (IV + salt + ciphertext, base64-encoded)
     *
     * @throws RuntimeException If encryption fails
     */
    public function encrypt(string $plaintext): string
    {
        $iv = random_bytes(self::IV_BYTE_LENGTH);
        $salt = random_bytes(self::SALT_BYTE_LENGTH);

        $secretKey = $this->deriveKey($salt);

        $cipherText = openssl_encrypt(
            $plaintext,
            self::CIPHER_ALGORITHM,
            $secretKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($cipherText === false) {
            throw new RuntimeException('Encryption failed.');
        }

        return base64_encode($iv) . base64_encode($salt) . base64_encode($cipherText);
    }

    /**
     * Set the decryption key.
     *
     * @param string $decryptKey The decryption key provided by PaperScorer
     *
     * @return self
     */
    public function setDecryptKey(string $decryptKey): self
    {
        $this->decryptKey = $decryptKey;

        return $this;
    }

    /**
     * Set the encrypted content to decrypt.
     *
     * @param string $encryptedContent The encrypted payload from PaperScorer
     *
     * @return self
     */
    public function setEncryptedContent(string $encryptedContent): self
    {
        $this->encryptedContent = $encryptedContent;

        return $this;
    }

    /**
     * Derive a 16-byte AES key from the decrypt key and the (raw) salt using SHA-256.
     *
     * @param string $salt The raw salt bytes
     *
     * @return string The 16-byte derived key
     */
    private function deriveKey(string $salt): string
    {
        return substr(
            hash(self::HASH_ALGORITHM, $this->decryptKey . $salt, true),
            0,
            self::AES_KEY_LENGTH
        );
    }
}
