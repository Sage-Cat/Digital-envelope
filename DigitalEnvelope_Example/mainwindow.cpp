#include "mainwindow.h"
#include "ui_mainwindow.h"

using namespace DigitalEnvelope;

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    Q_ASSERT(DigitalEnvelope::testDigitalEnvelopeSystem());

    generateKeysForPerson(_sender);
    generateKeysForPerson(_receiver);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_encrypt_clicked()
{
    if (ui->line_message->text().isEmpty())
        return;

    unique_ptr<Data> data { new Data };
    data->sessionKey = generateSessionKey();
    data->sender = _sender;
    data->receiver = _receiver;
    data->message = ui->line_message->text().toUtf8();

    _data = *data;

    // create envelope
    _envelope = *createEnvelope(std::move(data));

    // print out session key
    ui->text_sessionKey->setText(QString::fromUtf8(_data.sessionKey.toHex().toLower()));

    // print out envelope
    QStringList A {
        "--- Encoded session key (RSA) --- \n" + QString::fromUtf8(_envelope.A.toHex().toLower()),
        "--- Encrypted message (CAST-128) --- \n" + QString::fromUtf8(_envelope.B.toHex().toLower()),
        "--- Digital signature (RSA) --- \n" + QString::fromUtf8(_envelope.C.toHex().toLower())
    };
    ui->text_envelope->setText(A.join("\n\n"));
}

void MainWindow::on_btn_decrypt_clicked()
{
    unique_ptr<Envelope> envelope { new Envelope };
    *envelope = _envelope;

    // Unpack envelope
    _data = *openEnvelope(std::move(envelope), _sender, _receiver);

    QStringList result {
        "Resulting message: " + _data.message,
        _data.isCorrect ? "Signature is correct." : "Signature is wrong!!!"
    };

    ui->text_result->setText(result.join("\n"));
}

void MainWindow::on_btn_clear_clicked()
{
    ui->line_message->clear();
    ui->text_envelope->clear();
    ui->text_sessionKey->clear();
    ui->text_result->clear();
}
