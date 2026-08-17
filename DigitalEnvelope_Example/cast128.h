#pragma once
#include <cstdint>
#include <vector>
static const int keyLength = 128;
static const int blockLength = 64;
static const int keysCount = 32;
static const int roundCount = 16;

class Cast128 {
public:
    typedef uint32_t uint;
    typedef uint8_t uint8;
    typedef uint Key[keyLength / 8];
    struct Block {
        uint Msg[blockLength / 32];
    };

private:
    static Cast128::uint8 getByte(const Cast128::uint* key, Cast128::uint8 i);
    static Cast128::uint* generateKeys(const Cast128::Key key);
    typedef uint sBlock[256];
    static const sBlock S1;
    static const sBlock S2;
    static const sBlock S3;
    static const sBlock S4;
    static const sBlock S5;
    static const sBlock S6;
    static const sBlock S7;
    static const sBlock S8;

public:
    static Block encrypt(const Key key, const Block msg);
    static Block decrypt(const Key key, const Block msg);
    static std::vector<uint8> encryptBytes(const std::vector<uint8>& input, const Key key);
    static std::vector<uint8> decryptBytes(const std::vector<uint8>& input, const Key key);
    static uint sumMod2_32(uint a, uint b);
    static Block go(const Key key, const Block msg, bool isEncrypt);
    static uint subtractMod2_32(uint a, uint b);
    static uint cyclicShift(uint x, uint8 shift);
    static void splitI(uint I, uint8* Ia, uint8* Ib, uint8* Ic, uint8* Id);
};
