project(s3fs)

cmake_minimum_required(VERSION 2.8)

include_directories("/usr/include/libxml2")

SET(GCC_OPENSSL_CRYPTO_FLAGS "-lcrypto")
SET(GCC_LIBCURL_FLAGS "-lcurl")
SET(GCC_LIBFUSE_FLAGS "-lfuse")
SET(GCC_LIBXML2_FLAGS "-lxml2")
SET(GCC_FILE_OFFSET_BITS "-D_FILE_OFFSET_BITS=64")

SET(CMAKE_CXX_FLAGS "${GCC_OPENSSL_CRYPTO_FLAGS} ${GCC_LIBCURL_FLAGS} ${GCC_LIBFUSE_FLAGS} ${GCC_LIBXML2_FLAGS} ${GCC_FILE_OFFSET_BITS} -std=c++11")

add_executable(s3fs crypto.cpp s3fs.cpp s3fs_util.cpp cache.cpp curl.cpp fdcache.cpp string_util.cpp)

install(TARGETS s3fs RUNTIME DESTINATION bin)
