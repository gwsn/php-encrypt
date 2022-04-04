<?php declare(strict_types=1);
namespace GWSN\Encrypt;

use Exception;

class Encryptor
{
    /** @var string $secretKey */
    private string $secretKey;

    /**
     * @param string $secretKey
     */
    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }

    /**
     * @return string
     */
    public function getSecretKey(): string
    {
        return $this->secretKey;
    }

    /**
     * @param string $secretKey
     * @return Encryptor
     */
    public function setSecretKey(string $secretKey): Encryptor
    {
        $this->secretKey = $secretKey;
        return $this;
    }

    /**
     * Encrypt a message
     *
     * @param string $message - message to encrypt
     * @param string|null $key - optional to provide with different encryption key
     * @return string
     * @throws \SodiumException
     */
    function encrypt(string $message, string $key = null): string
    {
        if ($key === null) {
            $key = $this->getSecretKey();
        }

        if ($key === null || mb_strlen($key, '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new Exception('Key is not the correct! (size must be 32 bytes).');
        }


        $nonce = random_bytes(
            SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        );

        $cipher = base64_encode(
            $nonce .
            sodium_crypto_secretbox(
                $message,
                $nonce,
                $key
            )
        );
        sodium_memzero($message);
        sodium_memzero($key);
        return $cipher;
    }

    /**
     * Decrypt a message
     *
     * @param string $encrypted - message encrypted with safeEncrypt()
     * @param string|null $key - optional to provide with different encryption key
     * @return string
     * @throws \SodiumException
     */
    function decrypt(string $encrypted, string $key = null): string
    {
        if ($key === null) {
            $key = $this->getSecretKey();
        }

        if ($key === null || mb_strlen($key, '8bit') !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new Exception('Key is not the correct! (size must be 32 bytes).');
        }


        $decoded = base64_decode($encrypted, true);
        if ($decoded === false) {
            throw new Exception('Scream bloody murder, the encoding failed');
        }
        if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
            throw new Exception('Scream bloody murder, the message was truncated');
        }
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plain = sodium_crypto_secretbox_open(
            $ciphertext,
            $nonce,
            $key
        );
        if ($plain === false) {
            throw new Exception('the message was tampered with in transit');
        }
        sodium_memzero($ciphertext);
        sodium_memzero($key);
        return $plain;
    }

}
