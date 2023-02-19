include(FetchContent)
FetchContent_Populate(zlib
    # TODO: we need a method of supplying a local cache of this file.
    URL http://www.zlib.net/zlib-1.2.13.tar.gz
    URL_HASH SHA256=b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30
)
set(ZLIBDIR ${CMAKE_BINARY_DIR}/zlib-src)

list(APPEND ZLIBFILES inftrees.c infback.c compress.c inffast.c adler32.c uncompr.c inflate.c deflate.c crc32.c trees.c zutil.c)
list(APPEND ZLIBFILES gzclose.c gzread.c gzwrite.c gzlib.c)
list(TRANSFORM ZLIBFILES PREPEND ${ZLIBDIR}/)
add_library(zlib ${LIBSTYLE} ${ZLIBFILES})
target_include_directories(zlib PUBLIC ${ZLIBDIR})


