#include "cast128.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
bool expect(bool condition, const char* description)
{
    if (!condition) {
        std::cerr << "FAIL: " << description << '\n';
    }
    return condition;
}
}

int main()
{
    bool ok = true;

    // RFC 2144, Appendix B.1: full 128-bit key known-answer test.
    Cast128::Key key { 0x01234567, 0x12345678, 0x23456789, 0x3456789a };
    const Cast128::Block plaintext { 0x01234567, 0x89abcdef };
    const Cast128::Block expectedCiphertext { 0x238b4fe5, 0x847e44b2 };
    const auto ciphertext = Cast128::encrypt(key, plaintext);
    ok &= expect(ciphertext.Msg[0] == expectedCiphertext.Msg[0]
            && ciphertext.Msg[1] == expectedCiphertext.Msg[1],
        "RFC 2144 CAST-128 encryption vector");

    const auto decryptedBlock = Cast128::decrypt(key, ciphertext);
    ok &= expect(decryptedBlock.Msg[0] == plaintext.Msg[0]
            && decryptedBlock.Msg[1] == plaintext.Msg[1],
        "RFC 2144 CAST-128 decryption vector");

    const std::vector<Cast128::uint8> binaryMessage { 0x00, 0x01, 0x00, 0xff, 0x10, 0x00, 0x00, 0x00 };
    const auto encryptedBytes = Cast128::encryptBytes(binaryMessage, key);
    ok &= expect(encryptedBytes.size() == 16, "PKCS#7 adds a full block to aligned plaintext");
    ok &= expect(Cast128::decryptBytes(encryptedBytes, key) == binaryMessage,
        "binary data and trailing zero bytes round-trip");

    const std::vector<Cast128::uint8> emptyMessage;
    ok &= expect(Cast128::decryptBytes(Cast128::encryptBytes(emptyMessage, key), key).empty(),
        "empty plaintext round-trips");

    auto damaged = encryptedBytes;
    damaged.back() ^= 0xff;
    try {
        static_cast<void>(Cast128::decryptBytes(damaged, key));
        ok &= expect(false, "invalid padding is rejected");
    } catch (const std::invalid_argument&) {
    }

    return ok ? 0 : 1;
}
