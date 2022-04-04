<?php
namespace UnitTests\GWSN\Encrypt;

use Exception;
use GWSN\Encrypt\Encryptor;
use PHPUnit\Framework\TestCase;

class EncryptorTest extends TestCase
{
    private Encryptor $encryptor;
    private string $validSecretKey;
    private string $customSecretKey;

    public function setUp(): void
    {
        $this->validSecretKey = '3RQrq2ptJ0QbaDU3gir8z830mLvt0Wr5';
        $this->customSecretKey = 'I4cAnCVAamz9nu8iIB3NxL2ihpj2Gjej';
        $this->encryptor = new Encryptor($this->validSecretKey);
    }

    public function testConstruct() {
        $this->assertEquals($this->validSecretKey, $this->encryptor->getSecretKey());
    }

    public function testSecretKey() {
        $this->assertEquals($this->validSecretKey, $this->encryptor->getSecretKey());

        $this->encryptor->setSecretKey('testSecretKey');
        $this->assertEquals('testSecretKey', $this->encryptor->getSecretKey());
    }

    public function testEncryptAndDecrypt() {
        $encryptedWithSecretKey =$this->encryptor->encrypt('testContent');
        $result =$this->encryptor->decrypt($encryptedWithSecretKey);

        $this->assertEquals('testContent', $result);
    }

    public function testEncryptAndDecryptWithCustomKey() {
        $encryptedWithCustomKey =$this->encryptor->encrypt('testContent', $this->customSecretKey);
        $result =$this->encryptor->decrypt($encryptedWithCustomKey, $this->customSecretKey);

        $this->assertEquals('testContent', $result);
    }

    public function testEncryptWithKeyException() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Key is not the correct! (size must be 32 bytes).');

        $this->encryptor->encrypt('content', 'test');
    }

    public function testDecryptWithKeyException() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Key is not the correct! (size must be 32 bytes).');

        $this->encryptor->decrypt('content', 'test');
    }

    public function testDecryptWithInvalidEncryptedString() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Scream bloody murder, the encoding failed');

        $this->encryptor->decrypt('[\|/]');
    }

    public function testDecryptWithWrongEncryptedString() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Scream bloody murder, the message was truncated');

        $this->encryptor->decrypt('content');
    }

    public function testDecryptWithWrongSecretKey() {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('the message was tampered with in transit');

        $encryptedWithCustomKey =$this->encryptor->encrypt('testContent', $this->customSecretKey);
        $this->encryptor->decrypt($encryptedWithCustomKey, $this->validSecretKey);
    }
}
