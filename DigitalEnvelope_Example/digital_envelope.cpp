#include "digital_envelope.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QtEndian>

#include <exception>
#include <fstream>
#include <iostream>
#include <string>

#include <cast128.h>
#include <qrsaencryption.h>

namespace DigitalEnvelope {

/*!
 * \brief createEnvelope pack an envelop using struct Data
 * \note sender do not need to have his publicKey
 * \note receiver do not need to have his privateKey
 * \return struct Envelope
 */
unique_ptr<Envelope> createEnvelope(unique_ptr<Data> data)
{
    Q_ASSERT(!data->receiver.publicKey.isEmpty());
    Q_ASSERT(!data->sender.privateKey.isEmpty());

    QRSAEncryption rsa(QRSAEncryption::Rsa::RSA_64);
    QCryptographicHash sha1(QCryptographicHash::Sha1);
    unique_ptr<Envelope> envelope { new Envelope };

    // A
    envelope->A = rsa.encode(data->sessionKey, data->receiver.publicKey);

    // B
    envelope->B = encodeCAST128(data->message, data->sessionKey);

    // C
    QByteArray hash = sha1.hash(data->message, QCryptographicHash::Sha1);
    envelope->C = rsa.encode(hash, data->sender.privateKey);

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
    Q_ASSERT(!sender.publicKey.isEmpty());
    Q_ASSERT(!receiver.privateKey.isEmpty());

    QRSAEncryption rsa(QRSAEncryption::Rsa::RSA_64);
    QCryptographicHash sha1(QCryptographicHash::Sha1);
    unique_ptr<Data> data { new Data };

    // saving sender and receiver
    data->sender = sender;
    data->receiver = receiver;

    // A
    data->sessionKey = rsa.decode(envelope->A, receiver.privateKey);

    // B
    data->message = decodeCAST128(envelope->B, data->sessionKey);

    // C
    QByteArray hash = sha1.hash(data->message, QCryptographicHash::Sha1);
    data->isCorrect = hash == rsa.decode(envelope->C, sender.publicKey);

    return data;
}

QByteArray generateSessionKey()
{
    QRandomGenerator keyGen;
    QByteArray key;
    key.setNum(keyGen.generate64());

    return key;
}

void generateKeysForPerson(Person& person)
{
    QRSAEncryption keyGen(QRSAEncryption::Rsa::RSA_64);
    keyGen.generatePairKey(person.publicKey, person.privateKey);
}

QByteArray encodeCAST128(QByteArray message, QByteArray key)
{
    QByteArray encodedText {};

    std::string outFileKey { "out.txt" };
    std::string inFileKey { "input.txt" };
    std::string keyFileKey { "key.txt" };

    // MSG to file
    {
        std::ofstream toInFile(inFileKey);
        toInFile << message.toStdString();
        toInFile.close();
    }

    // Key to file
    {
        std::ofstream toKeyFile(keyFileKey);
        toKeyFile << key.toStdString();
        toKeyFile.close();
    }

    try {
        Cast128::Key cast128Key;
        Cast128::readKey(keyFileKey, &cast128Key);
        Cast128::encryptFile(inFileKey, outFileKey, cast128Key);

        {
            std::ifstream fromOutFile(outFileKey);
            std::string text {};
            fromOutFile >> text;
            encodedText = QByteArray::fromStdString(text);
            fromOutFile.close();
        }

    } catch (std::exception& e) {
        std::cout << e.what();
    }

    Q_ASSERT(!encodedText.isEmpty());

    return encodedText;
}

QByteArray decodeCAST128(QByteArray encodedText, QByteArray key)
{
    QByteArray message {};

    std::string outFileKey { "out.txt" };
    std::string inFileKey { "input.txt" };
    std::string keyFileKey { "key.txt" };

    // EncodedText to file
    {
        std::ofstream toInFile(inFileKey);
        toInFile << encodedText.toStdString();
        toInFile.close();
    }

    // Key to file
    {
        std::ofstream toKeyFile(keyFileKey);
        toKeyFile << key.toStdString();
        toKeyFile.close();
    }

    try {
        Cast128::Key cast128Key;
        Cast128::readKey(keyFileKey, &cast128Key);
        Cast128::decryptFile(outFileKey, outFileKey, cast128Key);

        {
            std::ifstream fromOutFile(outFileKey);
            std::string text {};
            fromOutFile >> text;
            message = QByteArray::fromStdString(text);
            fromOutFile.close();
        }

    } catch (std::exception& e) {
        std::cout << e.what();
    }

    Q_ASSERT(!message.isEmpty());

    return message;
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

    data->message = "Test_message!!!";

    // Create envelope
    unique_ptr<Envelope> createdEnvelope = createEnvelope(std::move(data));
    *logEnvelope = *createdEnvelope;

    // Unpack envelope
    *logData = *openEnvelope(std::move(createdEnvelope), sender, receiver);

    return logData->isCorrect;
}

}
