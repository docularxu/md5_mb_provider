cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  md5_mb_prov
  VERSION 0.1
  DESCRIPTION "A provider of MD5 multi-buffer implementation"
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

set(OPENSSL_CRYPTO_LIBRARY "/usr/local/lib/libcrypto.so.3")
set(OPENSSL_CRYPTO_LIBRARIES "/usr/local/lib/libcrypto.so.3")
set(OPENSSL_INCLUDE_DIR "/usr/local/include")
MESSAGE("OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
MESSAGE("OPENSSL_CRYPTO_LIBRARIES=${OPENSSL_CRYPTO_LIBRARIES}")
MESSAGE("OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")

add_subdirectory(src)
