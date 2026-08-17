TEMPLATE = subdirs
CONFIG += ordered

minigmp.file = Qt-Secret/src/mini-gmp/GMP.pro
qt_secret.file = Qt-Secret/src/Qt-Secret.pro
qt_secret.depends = minigmp
digital_envelope.file = DigitalEnvelope_Example/DigitalEnvelope_Example.pro
digital_envelope.depends = qt_secret

SUBDIRS += minigmp qt_secret digital_envelope
