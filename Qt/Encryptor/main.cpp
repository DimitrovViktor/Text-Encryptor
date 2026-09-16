#include "encryptor.h"
#include <QApplication>
#include "sodium/sodium.h"

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        return 1;
    }
    QApplication app(argc, argv);
    Encryptor window;
    window.show();
    return app.exec();
}
