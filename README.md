# Digital Envelope

A small Qt 5 desktop demonstration of a digital-envelope workflow. The sender encrypts a 128-bit CAST-128 session key with the receiver's toy RSA public key, encrypts the message with CAST-128, and attaches a SHA-256 digest transformed with the sender's toy RSA private key. The receiver reverses those steps and compares the digest.

> **Educational software only.** This is not a secure messaging implementation. It uses 64-bit textbook RSA from an old Qt-Secret snapshot, CAST-128 in ECB mode, no authenticated encryption or standard signature/padding scheme, and displays private keys in the GUI. Do not use it for sensitive data or as a basis for production cryptography.

## Build

Ubuntu 24.04 needs a C++17 compiler, `make`, `qt5-qmake`, and `qtbase5-dev`.

```sh
git clone --recurse-submodules https://github.com/Sage-Cat/Digital-envelope.git
cd Digital-envelope
mkdir build && cd build
qmake ../main.pro
make -j2
env LD_LIBRARY_PATH="../Qt-Secret/src/build/release:../Qt-Secret/src/mini-gmp/src/build/release" \
  ./DigitalEnvelope_Example/DigitalEnvelope_Example
```

For an existing clone, initialize the exact dependency commits recorded by Git:

```sh
git submodule update --init --recursive
```

## Tests

```sh
c++ -std=c++17 -Wall -Wextra -Wpedantic -Werror \
  -I DigitalEnvelope_Example tests/cast128_test.cpp \
  DigitalEnvelope_Example/cast128.cpp -o cast128_test
./cast128_test

mkdir -p build/tests && cd build/tests
qmake ../../tests/DigitalEnvelope_Tests.pro
make -j2
env LD_LIBRARY_PATH="../../Qt-Secret/src/build/release:../../Qt-Secret/src/mini-gmp/src/build/release" \
  ./DigitalEnvelope_Tests
```

The CAST-128 test includes the full-key known-answer vector from [RFC 2144, Appendix B.1](https://www.rfc-editor.org/rfc/rfc2144#appendix-B.1), binary and empty-message round trips, and padding rejection. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and license details.

The project is licensed under [LGPL-3.0](LICENSE).
