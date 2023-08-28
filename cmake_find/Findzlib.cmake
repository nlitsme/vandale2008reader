include(FetchContent)
FetchContent_Populate(zlib
    # TODO: we need a method of supplying a local cache of this file.
    URL https://www.zlib.net/zlib-1.3.tar.gz
    URL_HASH SHA256=ff0ba4c292013dbc27530b3a81e1f9a813cd39de01ca5e0f8bf355702efa593e
)
set(ZLIBDIR ${CMAKE_BINARY_DIR}/zlib-src)

list(APPEND ZLIBFILES inftrees.c infback.c compress.c inffast.c adler32.c uncompr.c inflate.c deflate.c crc32.c trees.c zutil.c)
#list(APPEND ZLIBFILES gzclose.c gzread.c gzwrite.c gzlib.c)  <-- build failure on macos because of missing include <unistd.h>
list(TRANSFORM ZLIBFILES PREPEND ${ZLIBDIR}/)
add_library(zlib ${LIBSTYLE} ${ZLIBFILES})
target_include_directories(zlib PUBLIC ${ZLIBDIR})


