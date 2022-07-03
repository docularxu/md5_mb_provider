# md5-mb-engine

An OpenSSL engine for md5. It uses isa-l_crypto's multi-buffer
md5 lib as backend.

## Build

Prerequisite: isa-l_crypto library should be built and installed.

Build as follows:

```
$ autoreconf -i
$ ./configure --libdir=/usr/local/lib/engines-1.1/
$ make
$ sudo make install
```

This will install md5_mb.so into /usr/local/lib/engines-1.1/

## Test with OpenSSL
```
openssl engine -t md5_mb
openssl md5 -engine md5_mb <testfile>
openssl speed -engine md5_mb -bytes 1000000 -seconds 3 md5

openssl speed -engine md5_mb -evp md5
openssl speed -engine md5_mb -multi 5 -evp md5
openssl dgst -engine md5_mb -md5 -hex <testfile>

# async mode
openssl speed -engine md5_mb -async_jobs 1 -evp md5
openssl speed -engine md5_mb -async_jobs 32 -evp md5
openssl speed -engine md5_mb -async_jobs 128 -evp md5

```
