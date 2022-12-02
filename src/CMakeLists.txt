cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  lib_md5_mb_prov
  VERSION 0.1
  DESCRIPTION "A library provider of MD5 multi-buffer implementation"
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

add_library(libmd5mbprov SHARED
	    common.c
	    mpsc.c
	    md5_mb_sw_isal_crypto_inf.c
	    prov_md5_mb.c)

set_target_properties(libmd5mbprov PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  OUTPUT_NAME "md5mbprov")
target_link_libraries(libmd5mbprov
		      ${OPENSSL_CRYPTO_LIBRARIES}
		      pthread
		      isal_crypto)
target_include_directories(libmd5mbprov PUBLIC ".")
target_include_directories(libmd5mbprov PUBLIC ${OPENSSL_INCLUDE_DIR})
