<?php

declare(strict_types=1);

namespace Tests\PaperScorer\DecrypterPhp;

use InvalidArgumentException;
use PaperScorer\DecrypterPhp\Decrypter;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class DecrypterTest extends TestCase
{
    /**
     * A known test vector generated with fixed IV and salt.
     *
     * Key:       "test-secret-key-123"
     * Plaintext: '{"score":95,"status":"completed"}'
     * IV:        0x0102030405060708090a0b0c0d0e0f10
     * Salt:      0xa1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1
     */
    private const TEST_KEY = 'test-secret-key-123';
    private const TEST_PLAINTEXT = '{"score":95,"status":"completed"}';
    private const TEST_PAYLOAD = 'AQIDBAUGBwgJCgsMDQ4PEA==oaKjpKWmp6ipsLGys7S1tre4ucDBRY02LalnHzdXBrTIv9n8T75utTPs+c2oG6ttJ3FMWThyMsswTi8hzeln34hsvRh7';

    // ---------------------------------------------------------------
    // Constructor tests
    // ---------------------------------------------------------------

    public function testConstructorAcceptsValidKey(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);
        $this->assertInstanceOf(Decrypter::class, $decrypter);
    }

    public function testConstructorThrowsOnEmptyKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Decrypter('');
    }

    // ---------------------------------------------------------------
    // decrypt() tests
    // ---------------------------------------------------------------

    public function testDecryptReturnsExpectedPlaintext(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);
        $decrypter->setEncryptedContent(self::TEST_PAYLOAD);

        $result = $decrypter->decrypt();

        $this->assertSame(self::TEST_PLAINTEXT, $result);
    }

    public function testDecryptThrowsWhenContentNotSet(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Encrypted content must be set before calling decrypt().');
        $decrypter->decrypt();
    }

    public function testDecryptThrowsOnShortPayload(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);
        $decrypter->setEncryptedContent('too-short');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Encrypted content is too short.');
        $decrypter->decrypt();
    }

    public function testDecryptThrowsOnWrongKey(): void
    {
        $decrypter = new Decrypter('wrong-key');
        $decrypter->setEncryptedContent(self::TEST_PAYLOAD);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Decryption failed.');
        $decrypter->decrypt();
    }

    public function testDecryptThrowsOnCorruptPayload(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);

        // Valid-length base64 segments (24 + 28 + ciphertext) but garbage content
        $fakeIv = base64_encode(random_bytes(16));        // 24 chars
        $fakeSalt = base64_encode(random_bytes(21));       // 28 chars
        $fakeCipher = base64_encode('not-real-ciphertext'); // arbitrary
        $decrypter->setEncryptedContent($fakeIv . $fakeSalt . $fakeCipher);

        $this->expectException(RuntimeException::class);
        $decrypter->decrypt();
    }

    // ---------------------------------------------------------------
    // encrypt() tests
    // ---------------------------------------------------------------

    public function testEncryptProducesDecryptablePayload(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);

        $payload = $decrypter->encrypt(self::TEST_PLAINTEXT);

        $this->assertSame(
            self::TEST_PLAINTEXT,
            $decrypter->setEncryptedContent($payload)->decrypt()
        );
    }

    public function testEncryptProducesDifferentPayloadsForSameInput(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);

        // A fresh random IV and salt are generated each call, so payloads differ
        $this->assertNotSame(
            $decrypter->encrypt(self::TEST_PLAINTEXT),
            $decrypter->encrypt(self::TEST_PLAINTEXT)
        );
    }

    // ---------------------------------------------------------------
    // Setter tests
    // ---------------------------------------------------------------

    public function testSetDecryptKeyChangesKey(): void
    {
        $decrypter = new Decrypter('initial-key');
        $decrypter->setEncryptedContent(self::TEST_PAYLOAD);

        // Switch to the correct key and verify decryption works
        $decrypter->setDecryptKey(self::TEST_KEY);
        $result = $decrypter->decrypt();

        $this->assertSame(self::TEST_PLAINTEXT, $result);
    }

    public function testSetEncryptedContentReplacesContent(): void
    {
        $decrypter = new Decrypter(self::TEST_KEY);

        // Set content, then replace it — only the latest should be used
        $decrypter->setEncryptedContent('will-be-replaced');
        $decrypter->setEncryptedContent(self::TEST_PAYLOAD);

        $this->assertSame(self::TEST_PLAINTEXT, $decrypter->decrypt());
    }

    // ---------------------------------------------------------------
    // Round-trip tests
    // ---------------------------------------------------------------

    public function testRoundTripEncryptDecrypt(): void
    {
        $decrypter = new Decrypter('round-trip-key');
        $plaintext = '{"user":"alice","role":"admin"}';

        $payload = $decrypter->encrypt($plaintext);

        $this->assertSame($plaintext, $decrypter->setEncryptedContent($payload)->decrypt());
    }

    public function testRoundTripWithDifferentPayloadSizes(): void
    {
        $decrypter = new Decrypter('payload-size-test');

        $payloads = [
            '',                    // empty string
            'a',                   // single character
            str_repeat('x', 256),  // longer than one AES block
        ];

        foreach ($payloads as $plaintext) {
            $payload = $decrypter->encrypt($plaintext);

            $this->assertSame(
                $plaintext,
                $decrypter->setEncryptedContent($payload)->decrypt(),
                'Failed for plaintext of length ' . strlen($plaintext)
            );
        }
    }
}
