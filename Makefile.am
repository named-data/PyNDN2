## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

lib_LTLIBRARIES = libndn-c.la

# Public C headers.
# NOTE: If a new directory is added, then add it to ndn_cpp_c_headers in include/Makefile.am.
ndn_cpp_c_headers = \
  include/ndn-cpp/ndn-cpp-config.h \
  include/ndn-cpp/c/common.h \
  include/ndn-cpp/c/control-parameters-types.h \
  include/ndn-cpp/c/data-types.h \
  include/ndn-cpp/c/errors.h \
  include/ndn-cpp/c/forwarding-flags.h \
  include/ndn-cpp/c/interest-types.h \
  include/ndn-cpp/c/key-types.h \
  include/ndn-cpp/c/name-types.h \
  include/ndn-cpp/c/encoding/element-reader-types.h \
  include/ndn-cpp/c/util/blob-types.h \
  include/ndn-cpp/c/util/dynamic-uint8-array-types.h

# Just the C code.
libndn_c_la_SOURCES = ${ndn_cpp_c_headers} \
  src/c/data.h \
  src/c/errors.c src/c/errors.h \
  src/c/forwarding-flags.c src/c/forwarding-flags-impl.h \
  src/c/interest.c src/c/interest.h \
  src/c/key-locator.h \
  src/c/name.c src/c/name.h \
  src/c/control-parameters.h \
  src/c/encoding/element-listener.h \
  src/c/encoding/element-reader.c src/c/encoding/element-reader.h \
  src/c/encoding/tlv-0_1_1-wire-format.c src/c/encoding/tlv-0_1_1-wire-format.h \
  src/c/encoding/tlv/tlv-data.c src/c/encoding/tlv/tlv-data.h \
  src/c/encoding/tlv/tlv-decoder.c src/c/encoding/tlv/tlv-decoder.h \
  src/c/encoding/tlv/tlv-encoder.c src/c/encoding/tlv/tlv-encoder.h \
  src/c/encoding/tlv/tlv-interest.c src/c/encoding/tlv/tlv-interest.h \
  src/c/encoding/tlv/tlv-key-locator.c src/c/encoding/tlv/tlv-key-locator.h \
  src/c/encoding/tlv/tlv-name.c src/c/encoding/tlv/tlv-name.h \
  src/c/encoding/tlv/tlv-control-parameters.c src/c/encoding/tlv/tlv-control-parameters.h \
  src/c/encoding/tlv/tlv-signature-info.c src/c/encoding/tlv/tlv-signature-info.h \
  src/c/encoding/tlv/tlv-structure-decoder.c src/c/encoding/tlv/tlv-structure-decoder.h \
  src/c/encoding/tlv/tlv.h \
  src/c/util/blob.h \
  src/c/util/dynamic-uint8-array.c src/c/util/dynamic-uint8-array.h \
  src/c/util/ndn_memory.c src/c/util/ndn_memory.h \
  src/c/util/ndn_realloc.c src/c/util/ndn_realloc.h \
  src/c/util/time.c src/c/util/time.h

pyexec_LTLIBRARIES = _pyndn.la
_pyndn_la_CFLAGS = $(PYTHON_CFLAGS) $(PYTHON_CPPFLAGS)
#_pyndn_la_LIBADD = ../src/pyndn.la
nodist__pyndn_la_SOURCES = src/pyndnmodule.c
_pyndn_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
