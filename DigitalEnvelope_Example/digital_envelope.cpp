#include "digital_envelope.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QtEndian>

#include <stdexcept>
#include <vector>

#include <cast128.h>
#include <qrsaencryption.h>

namespace DigitalEnvelope {

namespace {
constexpr QRSAEncryption::Rsa RSA_SIZE = QRSAEncryption::Rsa::RSA_64;

void toCASTKey(const QByteArray& key, Cast128::Key& result)
{
    if (key.size() != keyLength / 8) {
        throw std::invalid_argument("CAST-128 keys must be exactly 16 bytes");
    }

    for (int i = 0; i < 4; ++i) {
        result[i] = qFromBigEndian<quint32>(key.constData() + i * 4);
    }
}

std::vector<Cast128::uint8> toBytes(const QByteArray& data)
{
    if (data.isEmpty()) {
        return {};
    }
    const auto* begin = reinterpret_cast<const Cast128::uint8*>(data.constData());
    return { begin, begin + data.size() };
}

QByteArray fromBytes(const std::vector<Cast128::uint8>& data)
{
    return QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()));
}
}

/*!
 * \brief createEnvelope pack an envelop using struct Data
 * \note sender do not need to have his publicKey
 * \note receiver do not need to have his privateKey
 * \return struct Envelope
 */
unique_ptr<Envelope> createEnvelope(unique_ptr<Data> data)
{
    if (!data || data->receiver.publicKey.isEmpty() || data->sender.privateKey.isEmpty()) {
        throw std::invalid_argument("sender private key and receiver public key are required");
    }

    QRSAEncryption rsa(RSA_SIZE);
    unique_ptr<Envelope> envelope = std::make_unique<Envelope>();

    // A
    envelope->A = rsa.encode(data->sessionKey, data->receiver.publicKey, QRSAEncryption::BlockSize::OneByte);

    // B
    envelope->B = encodeCAST128(data->message, data->sessionKey);

    // C
    QByteArray hash = QCryptographicHash::hash(data->message, QCryptographicHash::Sha256);
    envelope->C = rsa.encode(hash, data->sender.privateKey, QRSAEncryption::BlockSize::OneByte);

    return envelope;
}

/*!
 * \brief openEnvelope unpack an envelop using struct Data
 * \note sender do not need to have his privateKey
 * \note receiver do not need to have his publicKey
 * \return struct Data
 */
unique_ptr<Data> openEnvelope(unique_ptr<Envelope> envelope, Person& sender, Person& receiver)
{
    if (!envelope || sender.publicKey.isEmpty() || receiver.privateKey.isEmpty()) {
        throw std::invalid_argument("envelope, sender public key and receiver private key are required");
    }

    QRSAEncryption rsa(RSA_SIZE);
    unique_ptr<Data> data = std::make_unique<Data>();

    // saving sender and receiver
    data->sender = sender;
    data->receiver = receiver;

    // A
    data->sessionKey = rsa.decode(envelope->A, receiver.privateKey, QRSAEncryption::BlockSize::OneByte);

    // B
    data->message = decodeCAST128(envelope->B, data->sessionKey);

    // C
    QByteArray hash = QCryptographicHash::hash(data->message, QCryptographicHash::Sha256);
    data->isCorrect = hash
        == rsa.decode(envelope->C, sender.publicKey, QRSAEncryption::BlockSize::OneByte);

    return data;
}

QByteArray generateSessionKey()
{
    QByteArray key(keyLength / 8, Qt::Uninitialized);
    auto* generator = QRandomGenerator::system();
    qToBigEndian<quint64>(generator->generate64(), key.data());
    qToBigEndian<quint64>(generator->generate64(), key.data() + sizeof(quint64));

    return key;
}

void generateKeysForPerson(Person& person)
{
    QRSAEncryption keyGenerator(RSA_SIZE);
    if (!keyGenerator.generatePairKey(person.publicKey, person.privateKey)) {
        throw std::runtime_error("RSA key generation failed");
    }
}

QByteArray encodeCAST128(QByteArray message, QByteArray key)
{
    Cast128::Key cast128Key {};
    toCASTKey(key, cast128Key);
    return fromBytes(Cast128::encryptBytes(toBytes(message), cast128Key));
}

QByteArray decodeCAST128(QByteArray encodedText, QByteArray key)
{
    Cast128::Key cast128Key {};
    toCASTKey(key, cast128Key);
    return fromBytes(Cast128::decryptBytes(toBytes(encodedText), cast128Key));
}

bool testDigitalEnvelopeSystem(shared_ptr<Data> logData, shared_ptr<Envelope> logEnvelope)
{
    Person
        sender {},
        receiver {};
    generateKeysForPerson(sender);
    generateKeysForPerson(receiver);

    unique_ptr<Data> data = std::make_unique<Data>();
    data->sessionKey = generateSessionKey();
    data->sender = sender;
    data->receiver = receiver;

    data->message = QByteArray("Test\0message\0", 13);

    // Create envelope
    unique_ptr<Envelope> createdEnvelope = createEnvelope(std::move(data));
    *logEnvelope = *createdEnvelope;

    // Unpack envelope
    *logData = *openEnvelope(std::move(createdEnvelope), sender, receiver);

    return logData->isCorrect;
}

}
