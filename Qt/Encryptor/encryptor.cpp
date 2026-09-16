#include "encryptor.h"
#include "ui_Encryptor.h"

#include <cstring>
#include <algorithm>
#include <unordered_map>

#include "argon/argon2.h"
#include "sodium/sodium.h"

static const uint32_t ALPHABET_POOL[] = {
    0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,
    0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,0x0420,0x0421,0x0422,0x0423,
    0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,
    0x042E,0x042F,
    0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,
    0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,0x0440,0x0441,0x0442,0x0443,
    0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044A,0x044B,0x044C,0x044D,
    0x044E,0x044F,

    0x0621,0x0622,0x0623,0x0624,0x0625,0x0626,0x0627,0x0628,0x0629,0x062A,
    0x062B,0x062C,0x062D,0x062E,0x062F,0x0630,0x0631,0x0632,0x0633,0x0634,
    0x0635,0x0636,0x0637,0x0638,0x0639,0x063A,0x0641,0x0642,0x0643,0x0644,
    0x0645,0x0646,0x0647,0x0648,0x0649,0x064A,

    0x4E00,0x4E01,0x4E03,0x4E07,0x4E08,0x4E09,0x4E0A,0x4E0B,0x4E0D,0x4E0E,
    0x4E10,0x4E11,0x4E13,0x4E14,0x4E16,0x4E18,0x4E19,0x4E1A,0x4E1B,0x4E1C,
    0x4E1D,0x4E22,0x4E24,0x4E25,0x4E27,0x4E2A,0x4E2D,0x4E30,0x4E32,0x4E34,
    0x4E38,0x4E39,0x4E3A,0x4E3B,0x4E3D,0x4E3E,0x4E43,0x4E45,0x4E48,0x4E49,
    0x4E4B,0x4E4C,0x4E4E,0x4E4F,0x4E50,0x4E52,0x4E53,0x4E54,0x4E56,0x4E58,
    0x4E59,0x4E5D,0x4E5E,0x4E5F,0x4E60,0x4E61,0x4E66,0x4E70,0x4E71,0x4E73,

    0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,0x0049,0x004A,
    0x004B,0x004C,0x004D,0x004E,0x004F,0x0050,0x0051,0x0052,0x0053,0x0054,
    0x0055,0x0056,0x0057,0x0058,0x0059,0x005A,
    0x0061,0x0062,0x0063,0x0064,0x0065,0x0066,0x0067,0x0068,0x0069,0x006A,
    0x006B,0x006C,0x006D,0x006E,0x006F,0x0070,0x0071,0x0072,0x0073,0x0074,
    0x0075,0x0076,0x0077,0x0078,0x0079,0x007A,

    0x3041,0x3042,0x3043,0x3044,0x3045,0x3046,0x3047,0x3048,0x3049,0x304A,
    0x304B,0x304C,0x304D,0x304E,0x304F,0x3050,0x3051,0x3052,0x3053,0x3054,
    0x3055,0x3056,0x3057,0x3058,0x3059,0x305A,0x305B,0x305C,0x305D,0x305E,
    0x305F,0x3060,0x3061,0x3062,0x3063,0x3064,0x3065,0x3066,0x3067,0x3068,
    0x3069,0x306A,0x306B,0x306C,0x306D,0x306E,0x306F,0x3070,0x3071,0x3072,
    0x3073,0x3074,0x3075,0x3076,0x3077,0x3078,0x3079,0x307A,0x307B,0x307C,

    0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039A,
    0x039B,0x039C,0x039D,0x039E,0x039F,0x03A0,0x03A1,0x03A3,0x03A4,0x03A5,
    0x03A6,0x03A7,0x03A8,0x03A9,
    0x03B1,0x03B2,0x03B3,0x03B4,0x03B5,0x03B6,0x03B7,0x03B8,0x03B9,0x03BA,
    0x03BB,0x03BC,0x03BD,0x03BE,0x03BF,0x03C0,0x03C1,0x03C3,0x03C4,0x03C5,
    0x03C6,0x03C7,0x03C8,0x03C9,
};

static constexpr size_t POOL_SIZE = sizeof(ALPHABET_POOL) / sizeof(ALPHABET_POOL[0]);

Encryptor::Encryptor(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::Encryptor) {
    ui->setupUi(this);
    connect(ui->pwd_set, &QPushButton::clicked, this, &Encryptor::onSetPassword);
    connect(ui->encr_btn, &QPushButton::clicked, this, &Encryptor::onEncrypt);
    connect(ui->decr_btn, &QPushButton::clicked, this, &Encryptor::onDecrypt);
}

Encryptor::~Encryptor() {
    delete ui;
}

void Encryptor::setStatus(const QString &message) {
    ui->statusbar->showMessage(message, 5000);
}

void Encryptor::onSetPassword() {
    if (m_passwordSet) {
        m_passwordSet = false;
        m_hash.clear();
        m_password.clear();
        m_charTable.clear();
        ui->pwd_text->setReadOnly(false);
        ui->pwd_text->clear();
        ui->pwd_set->setText("Set");
        setStatus("Password cleared. Enter a new one.");
        return;
    }
    m_password = ui->pwd_text->text().toStdString();
    if (m_password.empty()) {
        setStatus("Password cannot be empty.");
        return;
    }
    m_hash = hashPassword(m_password);
    if (m_hash.empty()) {
        setStatus("Hashing failed.");
        return;
    }
    m_charTable = buildCharTable(m_hash);
    m_passwordSet = true;
    ui->pwd_text->setReadOnly(true);
    ui->pwd_set->setText("Change");
    setStatus("Password set.");
}

void Encryptor::onEncrypt() {
    if (!m_passwordSet) {
        setStatus("Set a password first.");
        return;
    }
    std::string plaintext = ui->normtxt_edit->toPlainText().toStdString();
    if (plaintext.empty()) {
        setStatus("Enter text to encrypt.");
        return;
    }
    std::string result = encrypt(plaintext, m_hash);
    if (result.empty()) {
        setStatus("Encryption failed.");
        return;
    }
    ui->encrtxt_edit->setPlainText(QString::fromStdString(result));
    setStatus("Text encrypted.");
}

void Encryptor::onDecrypt() {
    if (!m_passwordSet) {
        setStatus("Set a password first.");
        return;
    }
    std::string ciphertext = ui->encrtxt_edit->toPlainText().toStdString();
    if (ciphertext.empty()) {
        setStatus("Enter text to decrypt.");
        return;
    }
    std::string result = decrypt(ciphertext, m_hash);
    if (result.empty()) {
        setStatus("Decryption failed. Wrong password or corrupted data.");
        return;
    }
    ui->normtxt_edit->setPlainText(QString::fromStdString(result));
    setStatus("Text decrypted.");
}

std::vector<unsigned char> Encryptor::hashPassword(const std::string &password) {
    const char *charKey = password.c_str();
    const char *salt = "100_200_Salting";
    std::vector<unsigned char> hash(crypto_secretbox_KEYBYTES);
    char encoded[128];

    int result = argon2_hash(
        2, 1 << 16, 1,
        charKey, strlen(charKey),
        salt, strlen(salt),
        hash.data(), hash.size(),
        encoded, sizeof(encoded),
        Argon2_id, ARGON2_VERSION_13
    );

    if (result != ARGON2_OK) {
        return {};
    }
    return hash;
}

std::vector<uint32_t> Encryptor::buildCharTable(const std::vector<unsigned char> &hash) {
    std::vector<uint32_t> pool(ALPHABET_POOL, ALPHABET_POOL + POOL_SIZE);

    uint64_t seed = 0;
    for (size_t i = 0; i < hash.size(); ++i) {
        seed ^= static_cast<uint64_t>(hash[i]) << ((i % 8) * 8);
    }

    for (size_t i = pool.size() - 1; i > 0; --i) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        size_t j = (seed >> 33) % (i + 1);
        std::swap(pool[i], pool[j]);
    }

    std::vector<uint32_t> table(pool.begin(), pool.begin() + 256);
    return table;
}

QString Encryptor::encodeBytesToChars(const std::vector<unsigned char> &data, const std::vector<uint32_t> &table) {
    QString result;
    result.reserve(data.size());
    for (unsigned char byte : data) {
        result.append(QChar(table[byte]));
    }
    return result;
}

std::vector<unsigned char> Encryptor::decodeCharsToBytes(const QString &text, const std::vector<uint32_t> &table) {
    std::unordered_map<uint32_t, unsigned char> reverse;
    for (int i = 0; i < 256; ++i) {
        reverse[table[i]] = static_cast<unsigned char>(i);
    }

    std::vector<unsigned char> result;
    result.reserve(text.size());
    for (QChar ch : text) {
        auto it = reverse.find(ch.unicode());
        if (it == reverse.end()) {
            return {};
        }
        result.push_back(it->second);
    }
    return result;
}

std::string Encryptor::encrypt(const std::string &plaintext, const std::vector<unsigned char> &hash) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(
        ciphertext.data(),
        (const unsigned char *)plaintext.data(), plaintext.size(),
        nonce, hash.data()
    );

    std::vector<unsigned char> combined(nonce, nonce + sizeof(nonce));
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

    QString encoded = encodeBytesToChars(combined, m_charTable);
    return encoded.toStdString();
}

std::string Encryptor::decrypt(const std::string &ciphertext, const std::vector<unsigned char> &hash) {
    QString qCiphertext = QString::fromStdString(ciphertext);
    std::vector<unsigned char> decoded = decodeCharsToBytes(qCiphertext, m_charTable);

    if (decoded.empty() || decoded.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return "";
    }

    const unsigned char *nonce = decoded.data();
    const unsigned char *cipher = decoded.data() + crypto_secretbox_NONCEBYTES;
    size_t cipher_len = decoded.size() - crypto_secretbox_NONCEBYTES;

    std::vector<unsigned char> decrypted(cipher_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(
            decrypted.data(), cipher, cipher_len,
            nonce, hash.data()) != 0) {
        return "";
    }

    return std::string((char *)decrypted.data(), decrypted.size());
}
