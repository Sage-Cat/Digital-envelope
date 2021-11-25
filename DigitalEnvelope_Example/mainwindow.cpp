#include "mainwindow.h"
#include "ui_mainwindow.h"

using namespace DigitalEnvelope;

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    Q_ASSERT(DigitalEnvelope::testDigitalEnvelopeSystem());

    on_btn_clear_clicked();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_btn_encrypt_clicked()
{
    if (ui->line_message->text().isEmpty())
        return;

    Person
        sender {},
        receiver {};
    sender.publicKey = QByteArray::fromHex(ui->line_sender_pub->text().toUtf8());
    sender.privateKey = QByteArray::fromHex(ui->line_sender_private->text().toUtf8());
    receiver.publicKey = QByteArray::fromHex(ui->line_receiver_pub->text().toUtf8());
    receiver.privateKey = QByteArray::fromHex(ui->line_receiver_private->text().toUtf8());

    unique_ptr<Data> data { new Data };
    data->sessionKey = QByteArray::fromHex(ui->line_sessionKey->text().toUtf8());
    data->sender = sender;
    data->receiver = receiver;
    data->message = ui->line_message->text().toUtf8();
    _data = *data;

    // create envelope
    _envelope = *createEnvelope(std::move(data));

    // print out envelope
    ui->line_A->setText(QString::fromUtf8(_envelope.A.toHex()));
    ui->line_B->setText(QString::fromUtf8(_envelope.B.toHex()));
    ui->line_C->setText(QString::fromUtf8(_envelope.C.toHex()));
}

void MainWindow::on_btn_decrypt_clicked()
{
    unique_ptr<Envelope> envelope { new Envelope };
    *envelope = _envelope;

    Person
        sender {},
        receiver {};
    sender.publicKey = QByteArray::fromHex(ui->line_sender_pub->text().toUtf8());
    sender.privateKey = QByteArray::fromHex(ui->line_sender_private->text().toUtf8());
    receiver.publicKey = QByteArray::fromHex(ui->line_receiver_pub->text().toUtf8());
    receiver.privateKey = QByteArray::fromHex(ui->line_receiver_private->text().toUtf8());

    envelope->A = QByteArray::fromHex(ui->line_A->text().toUtf8());
    envelope->B = QByteArray::fromHex(ui->line_B->text().toUtf8());
    envelope->C = QByteArray::fromHex(ui->line_C->text().toUtf8());

    // Unpack envelope
    _data = *openEnvelope(std::move(envelope), sender, receiver);

    QStringList result {
        "-- Resulting message --- \n " + _data.message,
        _data.isCorrect ? "Signature is correct." : "Signature is wrong!!!"
    };

    ui->text_result->setText(result.join("\n\n"));
}

void MainWindow::on_btn_clear_clicked()
{
    ui->line_message->clear();
    ui->line_A->clear();
    ui->line_B->clear();
    ui->line_C->clear();
    ui->line_sender_private->clear();
    ui->line_sender_pub->clear();
    ui->line_sessionKey->clear();
    ui->line_receiver_private->clear();
    ui->line_receiver_pub->clear();
    ui->text_result->clear();

    Person
        sender {},
        receiver {};
    QByteArray sessionKey {};

    generateKeysForPerson(sender);
    generateKeysForPerson(receiver);
    sessionKey = generateSessionKey();

    ui->line_sessionKey->setText(QString::fromUtf8(sessionKey.toHex()));
    ui->line_sender_pub->setText(QString::fromUtf8(sender.publicKey.toHex()));
    ui->line_sender_private->setText(QString::fromUtf8(sender.privateKey.toHex()));
    ui->line_receiver_pub->setText(QString::fromUtf8(receiver.publicKey.toHex()));
    ui->line_receiver_private->setText(QString::fromUtf8(receiver.privateKey.toHex()));
}
