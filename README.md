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

# md5-mb-provider

An OpenSSL v3.0 provider for md5. It uses isa-l_crypto's multi-buffer
md5 as backend.

## Build

```
mkdir build
cmake -S . -B build --log-level=DEBUG
cmake --build build --verbose
```

## Test with OpenSSL v3.0
```
openssl speed -provider-path [path-to-build]/build/src -provider libmd5mbprov -provider default -evp md5
```
Note: default provider is required generate a summary for speed. The test will take md5 implementation from libmd5mbprov.


```
openssl list  -provider-path /home/ubuntu/md5_mb_prov.git/build/src -provider libmd5mbprov -all-algorithms
```

Note: Expected result of 'openssl list':
```
Digests:
   Provided:
  { 1.2.840.113549.2.5, MD5, SSL3-MD5 } @ libmd5mbprov
```
