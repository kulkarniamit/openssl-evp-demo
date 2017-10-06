# openssl-evp-demo
Simple file encrypt-decrypt using OpenSSL EVP functions

## Prerequisites
* Any linux platform
* gcc
* make
* OpenSSL
* libssl-dev (Ubuntu) or equivalent OpenSSL development library
* Patience and enthusiasm to learn about EVP functions

## How to build?

Build a regular binary in `bin` 

`$ make all`

Build debug binary in `bin`

`$ make debug`

## How to clean?
`$ make clean`

## How to run?

```
$ ./bin/openssl_evp_demo testfile && sha256sum testfile decrypted_file
20492a4d0d84f8beb1767f6616229f85d44c2827b64bdbfb260ee12fa1109e0e  testfile
20492a4d0d84f8beb1767f6616229f85d44c2827b64bdbfb260ee12fa1109e0e  decrypted_file
```

Where, 

* `testfile` can be any of your file
* `decrypted_file` is the generated decrypted file

Same checksum represents a successful encryption and decryption
