#include "digital_envelope.h"

#include <QCoreApplication>

#include <iostream>

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);

    auto data = std::make_shared<DigitalEnvelope::Data>();
    auto envelope = std::make_shared<DigitalEnvelope::Envelope>();
    if (!DigitalEnvelope::testDigitalEnvelopeSystem(data, envelope)) {
        std::cerr << "digital envelope round-trip or signature verification failed\n";
        return 1;
    }
    if (data->message != QByteArray("Test\0message\0", 13)) {
        std::cerr << "binary message changed during the round-trip\n";
        return 1;
    }

    envelope->C[0] = static_cast<char>(envelope->C.at(0) ^ 1);
    auto checked = DigitalEnvelope::openEnvelope(
        std::make_unique<DigitalEnvelope::Envelope>(*envelope), data->sender, data->receiver);
    if (checked->isCorrect) {
        std::cerr << "modified signature was accepted\n";
        return 1;
    }

    return 0;
}
