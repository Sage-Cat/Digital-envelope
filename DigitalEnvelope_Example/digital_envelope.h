#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <cstdint>
#include <memory>
#include <string>

using std::string;
using std::unique_ptr;

namespace DigitalEnvelope {
typedef std::uint64_t uint;

struct Envelope {
    uint
        A {}, // Encrypted session key (RSA)
        B {}, // Encoded message (CAST-128)
        C {}; // Digital signature (RSA)
};

struct Person {
    uint
        publicKey {},
        privateKey {};
};

struct Data {
    string message {};
    Person
        sender {},
        receiver {};
};

/*!
 * \brief createEnvelope pack an envelop using struct Data
 * \note sender do not need to have his publicKey
 * \note receiver do not need to have his privateKey
 * \return struct Envelope
 */
unique_ptr<Envelope> createEnvelope(unique_ptr<Data> data);

/*!
 * \brief openEnvelope unpack an envelop using struct Data
 * \note sender do not need to have his privateKey
 * \note receiver do not need to have his publicKey
 * \return struct Data
 */
unique_ptr<Data> openEnvelope(unique_ptr<Envelope> envelope);

uint generateSessionKey();
void generateKeysForPerson(Person& person);
}

#endif // ENVELOPE_H
