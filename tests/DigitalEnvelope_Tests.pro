QT -= gui
CONFIG += console c++17 warn_on
CONFIG -= app_bundle
TEMPLATE = app
TARGET = DigitalEnvelope_Tests

SOURCES += \
    digital_envelope_test.cpp \
    ../DigitalEnvelope_Example/cast128.cpp \
    ../DigitalEnvelope_Example/digital_envelope.cpp

HEADERS += \
    ../DigitalEnvelope_Example/cast128.h \
    ../DigitalEnvelope_Example/digital_envelope.h

INCLUDEPATH += ../DigitalEnvelope_Example
include(../Qt-Secret/src/Qt-Secret.pri)
