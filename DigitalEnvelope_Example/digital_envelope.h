#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <QByteArray>
#include <cstdint>
#include <memory>

#include <QRandomGenerator>

using std::shared_ptr;
using std::unique_ptr;

namespace DigitalEnvelope {
typedef std::uint64_t uint;

const size_t BIT_RATE = 64; // for session, pub and priv keys

struct Envelope {
    QByteArray
        A {}, // Encrypted session key (RSA)
        B {}, // Encoded message (CAST-128)
        C {}; // Digital signature (RSA)
};

struct Person {
    QByteArray
        publicKey {},
        privateKey {};
};

struct Data {
    QByteArray message {};
    QByteArray sessionKey {};
    Person
        sender {},
        receiver {};
    bool isCorrect {};
};

static QRandomGenerator keyGen;

unique_ptr<Envelope> createEnvelope(unique_ptr<Data> data);
unique_ptr<Data> openEnvelope(unique_ptr<Envelope> envelope, Person& sender, Person& receiver);
bool testDigitalEnvelopeSystem(
    shared_ptr<Data> logData = std::make_shared<Data>(),
    shared_ptr<Envelope> logEnvelope = std::make_shared<Envelope>());

QByteArray encodeCAST128(QByteArray message, QByteArray key);
QByteArray decodeCAST128(QByteArray encodedText, QByteArray key);

QByteArray generateSessionKey();
void generateKeysForPerson(Person& person);
}

#endif // ENVELOPE_H
