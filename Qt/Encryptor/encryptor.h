#ifndef encryptor_H
#define encryptor_H

#include <QMainWindow>
#include <string>
#include <vector>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui { class Encryptor; }
QT_END_NAMESPACE

class Encryptor : public QMainWindow {
    Q_OBJECT

public:
    explicit Encryptor(QWidget *parent = nullptr);
    ~Encryptor();

private slots:
    void onSetPassword();
    void onEncrypt();
    void onDecrypt();

private:
    Ui::Encryptor *ui;
    std::string m_password;
    std::vector<unsigned char> m_hash;
    bool m_passwordSet = false;
    std::vector<uint32_t> m_charTable;

    std::vector<unsigned char> hashPassword(const std::string &password);
    std::vector<uint32_t> buildCharTable(const std::vector<unsigned char> &hash);
    QString encodeBytesToChars(const std::vector<unsigned char> &data, const std::vector<uint32_t> &table);
    std::vector<unsigned char> decodeCharsToBytes(const QString &text, const std::vector<uint32_t> &table);
    std::string encrypt(const std::string &plaintext, const std::vector<unsigned char> &hash);
    std::string decrypt(const std::string &ciphertext, const std::vector<unsigned char> &hash);
    void setStatus(const QString &message);
};

#endif
