cmake_minimum_required(VERSION 2.8.4)
project(sdfs)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES sdfs-client.c sdfs-server.c)
add_executable(sdfs-client sdfs-client.c network/tcp.c network/tcp.h network/dns.c network/dns.h crypto/encrypt.c crypto/encrypt.h crypto/mac.c crypto/mac.h crypto/tls.h crypto/tls.c output/console.c output/console.h crypto/pki.c crypto/pki.h)
add_executable(sdfs-server sdfs-server.c network/tcp.c network/tcp.h network/dns.c network/dns.h crypto/encrypt.c crypto/encrypt.h crypto/mac.c crypto/mac.h crypto/tls.h crypto/tls.c output/console.c output/console.h crypto/pki.c crypto/pki.h)

target_link_libraries(sdfs-client crypt glib-2.0 confuse)
target_link_libraries(sdfs-server crypt glib-2.0 confuse)

find_package (OpenSSL REQUIRED)
if (OPENSSL_FOUND)
    message(-- Found OpenSSL ${OPENSSL_VERSION})
    include_directories(${OPENSSL_INCLUDE_DIRS})
    target_link_libraries (sdfs-client ${OPENSSL_LIBRARIES})
    target_link_libraries (sdfs-server ${OPENSSL_LIBRARIES})

endif (OPENSSL_FOUND)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)
if (GLIB_PKG_FOUND)
    message(-- Found glib-2.0)
    include_directories(${GLIB_PKG_INCLUDE_DIRS})
    target_link_libraries(sdfs-client ${GLIB_PKG_LIBRARY_DIRS})
    target_link_libraries(sdfs-server ${GLIB_PKG_LIBRARY_DIRS})
endif (GLIB_PKG_FOUND)
