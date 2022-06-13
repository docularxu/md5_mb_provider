# uadk-engine

## Build

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
openssl engine -t uadk
openssl md5 -engine md5_mb <testfile>
openssl speed -engine md5_mb -bytes 1000000 -seconds 3 md5

openssl speed -engine md5_mb -evp md5
openssl speed -engine md5_mb -multi 5 -evp md5
openssl dgst -engine md5_mb -md5 -hex <testfile>
```
