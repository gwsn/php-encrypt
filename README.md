# PHP Encrypt/Decrypt content tooling
Simple tooling to encrypt and decrypt content

## Installation

You can install the package via composer:

``` bash
composer require gwsn/php-encrypt
```


## Plain Usage

``` bash
use GWSN/Encrypt/Encryptor;

$encryptor = new Encryptor('secretKey');

$encrypted = $encryptor->encrypt('content');

$decrypted = $encryptor->decrypt($encrypted);
```

## Use in Symfony

Add the following part to the `config/services.yaml`

* Where the kernel.secret should be set and a valid string of 32 characters, alternative you can set a random secret key 

```yaml
GWSN\Encrypt\Encryptor:
  arguments:
    $secretKey: '%kernel.secret%'
```

And you can use it in any function with dependency injection
```php

    private Encryptor $encryptor;

    public function __construct(Encryptor $encryptor)
    {
        $this->encryptor = $encryptor;
    }

    public function makeItSecret(string $content): string
    {
        return $this->encryptor->encrypt($content);
    }
    
    public function makeItReadable(string $content): string 
    {
        return $this->encryptor->decrypt($content);
    }
```


## Test

``` bash
composer run test
```

