## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# Public C headers.
ndn_cpp_c_headers = \
  include/ndn-cpp/ndn-cpp-config.h \
  include/ndn-cpp/c/common.h \
  include/ndn-cpp/c/control-parameters-types.h \
  include/ndn-cpp/c/control-response-types.h \
  include/ndn-cpp/c/data-types.h \
  include/ndn-cpp/c/delegation-set-types.h \
  include/ndn-cpp/c/errors.h \
  include/ndn-cpp/c/forwarding-flags.h \
  include/ndn-cpp/c/interest-types.h \
  include/ndn-cpp/c/key-types.h \
  include/ndn-cpp/c/name-types.h \
  include/ndn-cpp/c/network-nack-types.h \
  include/ndn-cpp/c/encoding/element-reader-types.h \
  include/ndn-cpp/c/encrypt/encrypted-content-types.h \
  include/ndn-cpp/c/encrypt/algo/encrypt-params-types.h \
  include/ndn-cpp/c/lp/incoming-face-id-types.h \
  include/ndn-cpp/c/lp/lp-packet-types.h \
  include/ndn-cpp/c/security/ec-private-key-types.h \
  include/ndn-cpp/c/security/ec-public-key-types.h \
  include/ndn-cpp/c/security/rsa-private-key-types.h \
  include/ndn-cpp/c/security/rsa-public-key-types.h \
  include/ndn-cpp/c/security/validity-period-types.h \
  include/ndn-cpp/c/transport/transport-types.h \
  include/ndn-cpp/c/util/blob-types.h \
  include/ndn-cpp/c/util/dynamic-uint8-array-types.h

# Public C++ headers.
ndn_cpp_cpp_headers = \
  include/ndn-cpp/lite/common-lite.hpp \
  include/ndn-cpp/lite/control-parameters-lite.hpp \
  include/ndn-cpp/lite/control-response-lite.hpp \
  include/ndn-cpp/lite/data-lite.hpp \
  include/ndn-cpp/lite/delegation-set-lite.hpp \
  include/ndn-cpp/lite/exclude-lite.hpp \
  include/ndn-cpp/lite/forwarding-flags-lite.hpp \
  include/ndn-cpp/lite/interest-lite.hpp \
  include/ndn-cpp/lite/key-locator-lite.hpp \
  include/ndn-cpp/lite/meta-info-lite.hpp \
  include/ndn-cpp/lite/name-lite.hpp \
  include/ndn-cpp/lite/network-nack-lite.hpp \
  include/ndn-cpp/lite/signature-lite.hpp \
  include/ndn-cpp/lite/encoding/element-listener-lite.hpp \
  include/ndn-cpp/lite/encoding/tlv-0_1_1-wire-format-lite.hpp \
  include/ndn-cpp/lite/encoding/tlv-0_2-wire-format-lite.hpp \
  include/ndn-cpp/lite/encrypt/encrypted-content-lite.hpp \
  include/ndn-cpp/lite/encrypt/algo/aes-algorithm-lite.hpp \
  include/ndn-cpp/lite/encrypt/algo/encrypt-params-lite.hpp \
  include/ndn-cpp/lite/lp/incoming-face-id-lite.hpp \
  include/ndn-cpp/lite/lp/lp-packet-lite.hpp \
  include/ndn-cpp/lite/security/ec-private-key-lite.hpp \
  include/ndn-cpp/lite/security/ec-public-key-lite.hpp \
  include/ndn-cpp/lite/security/rsa-private-key-lite.hpp \
  include/ndn-cpp/lite/security/rsa-public-key-lite.hpp \
  include/ndn-cpp/lite/security/validity-period-lite.hpp \
  include/ndn-cpp/lite/transport/tcp-transport-lite.hpp \
  include/ndn-cpp/lite/transport/udp-transport-lite.hpp \
  include/ndn-cpp/lite/transport/unix-transport-lite.hpp \
  include/ndn-cpp/lite/util/blob-lite.hpp \
  include/ndn-cpp/lite/util/crypto-lite.hpp \
  include/ndn-cpp/lite/util/dynamic-malloc-uint8-array-lite.hpp \
  include/ndn-cpp/lite/util/dynamic-uint8-array-lite.hpp

# Just the C code.
ndn_cpp_c_sources = ${ndn_cpp_c_headers} \
  src/c/control-parameters_c.c src/c/control-parameters.h \
  src/c/control-response.h \
  src/c/data.h \
  src/c/delegation-set.h \
  src/c/errors.c src/c/errors.h \
  src/c/forwarding-flags.c src/c/forwarding-flags-impl.h \
  src/c/interest_c.c src/c/interest.h \
  src/c/key-locator.h \
  src/c/name_c.c src/c/name.h \
  src/c/network-nack_c.c src/c/network-nack.h \
  src/c/encoding/element-listener.h \
  src/c/encoding/element-reader.c src/c/encoding/element-reader.h \
  src/c/encoding/tlv-0_2-wire-format_c.c src/c/encoding/tlv-0_2-wire-format.h \
  src/c/encoding/tlv/tlv-control-parameters.c src/c/encoding/tlv/tlv-control-parameters.h \
  src/c/encoding/tlv/tlv-control-response.c src/c/encoding/tlv/tlv-control-response.h \
  src/c/encoding/tlv/tlv-data.c src/c/encoding/tlv/tlv-data.h \
  src/c/encoding/tlv/tlv-delegation-set.c src/c/encoding/tlv/tlv-delegation-set.h \
  src/c/encoding/tlv/tlv-decoder.c src/c/encoding/tlv/tlv-decoder.h \
  src/c/encoding/tlv/tlv-encoder.c src/c/encoding/tlv/tlv-encoder.h \
  src/c/encoding/tlv/tlv-encrypted-content.c src/c/encoding/tlv/tlv-encrypted-content.h \
  src/c/encoding/tlv/tlv-interest.c src/c/encoding/tlv/tlv-interest.h \
  src/c/encoding/tlv/tlv-key-locator.c src/c/encoding/tlv/tlv-key-locator.h \
  src/c/encoding/tlv/tlv-lp-packet.c src/c/encoding/tlv/tlv-lp-packet.h \
  src/c/encoding/tlv/tlv-name.c src/c/encoding/tlv/tlv-name.h \
  src/c/encoding/tlv/tlv-signature-info.c src/c/encoding/tlv/tlv-signature-info.h \
  src/c/encoding/tlv/tlv-structure-decoder.c src/c/encoding/tlv/tlv-structure-decoder.h \
  src/c/encoding/tlv/tlv.h \
  src/c/encrypt/encrypted-content.h \
  src/c/encrypt/algo/aes-algorithm_c.c src/c/encrypt/algo/aes-algorithm.h \
  src/c/encrypt/algo/encrypt-params.h \
  src/c/lp/incoming-face-id_c.c src/c/lp/incoming-face-id.h \
  src/c/lp/lp-packet.h \
  src/c/security/ec-private-key.c src/c/util/ec-private-key.h \
  src/c/security/ec-public-key.c src/c/util/ec-public-key.h \
  src/c/security/rsa-private-key.c src/c/util/rsa-private-key.h \
  src/c/security/rsa-public-key.c src/c/util/rsa-public-key.h \
  src/c/security/validity-period.h \
  src/c/transport/socket-transport.c src/c/transport/socket-transport.h \
  src/c/transport/tcp-transport_c.c src/c/transport/tcp-transport.h \
  src/c/transport/udp-transport.h \
  src/c/transport/unix-transport.h \
  src/c/util/blob_c.c src/c/util/blob.h \
  src/c/util/crypto.c src/c/util/crypto.h \
  src/c/util/dynamic-uint8-array.c src/c/util/dynamic-uint8-array.h \
  src/c/util/ndn_memory.c src/c/util/ndn_memory.h \
  src/c/util/ndn_realloc.c src/c/util/ndn_realloc.h \
  src/c/util/time.c src/c/util/time.h

# C++ code and also the C code.
ndn_cpp_cpp_sources = ${ndn_cpp_c_sources} ${ndn_cpp_cpp_headers} \
  src/lite/control-parameters-lite.cpp \
  src/lite/control-response-lite.cpp \
  src/lite/data-lite.cpp \
  src/lite/delegation-set-lite.cpp \
  src/lite/exclude-lite.cpp \
  src/lite/forwarding-flags-lite.cpp \
  src/lite/interest-lite.cpp \
  src/lite/key-locator-lite.cpp \
  src/lite/meta-info-lite.cpp \
  src/lite/name-lite.cpp \
  src/lite/network-nack-lite.cpp \
  src/lite/signature-lite.cpp \
  src/lite/encoding/element-listener-lite.cpp \
  src/lite/encoding/tlv-0_2-wire-format-lite.cpp \
  src/lite/encrypt/encrypted-content-lite.cpp \
  src/lite/encrypt/algo/aes-algorithm-lite.cpp \
  src/lite/encrypt/algo/encrypt-params-lite.cpp \
  src/lite/lp/incoming-face-id-lite.cpp \
  src/lite/lp/lp-packet-lite.cpp \
  src/lite/security/ec-private-key-lite.cpp \
  src/lite/security/ec-public-key-lite.cpp \
  src/lite/security/rsa-private-key-lite.cpp \
  src/lite/security/rsa-public-key-lite.cpp \
  src/lite/security/validity-period-lite.cpp \
  src/lite/transport/tcp-transport-lite.cpp \
  src/lite/transport/udp-transport-lite.cpp \
  src/lite/transport/unix-transport-lite.cpp \
  src/lite/util/blob-lite.cpp \
  src/lite/util/crypto-lite.cpp \
  src/lite/util/dynamic-malloc-uint8-array-lite.cpp \
  src/lite/util/dynamic-uint8-array-lite.cpp

pyexec_LTLIBRARIES = _pyndn.la
_pyndn_la_CFLAGS = $(PYTHON_CFLAGS)
_pyndn_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
nodist__pyndn_la_SOURCES = ${ndn_cpp_cpp_sources} \
  src/pyndnmodule.cpp
_pyndn_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
