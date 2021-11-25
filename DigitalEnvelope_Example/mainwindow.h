#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "digital_envelope.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void on_btn_encrypt_clicked();
    void on_btn_decrypt_clicked();
    void on_btn_clear_clicked();

private:
    Ui::MainWindow* ui;

    DigitalEnvelope::Data _data;
    DigitalEnvelope::Envelope _envelope;
};
#endif // MAINWINDOW_H
