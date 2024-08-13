#include "../hsm/SDFCryptoProvider.h"
#include "../hsm/gmt0018.h"
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <memory>

using namespace hsm;

std::vector<byte> bHashVector = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
                                 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                                 0x61,
                                 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
                                 0x64,
                                 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
                                 0x63,
                                 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};

std::vector<byte> bHashStdResultVector = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38,
                                          0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e,
                                          0x57, 0x65,
                                          0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};


void verify(int loopRound, const Key &key, const char *signature, const std::string &libPath, size_t sessionPoolRound) {
    for (int i = 0; i < loopRound; i++) {
        SDFCryptoProvider &provider = SDFCryptoProvider::GetInstance(sessionPoolRound, libPath);
        bool verifyResult = false;
        unsigned int code = provider.Verify(key, SM2, bHashStdResultVector.data(), bHashStdResultVector.size(),
                                            hsm::sdfFromHex((char *) signature).data(), 64, &verifyResult);
        if (code != SDR_OK) {
            std::cout << "Verify failed" << std::endl;
        }
    }
}

void hash(int loopRound, size_t sessionPoolRound, char const *message, const std::string &libPath) {
    for (int i = 0; i < loopRound; i++) {
        std::vector<byte> hashResult(32);
        unsigned int len;
        SDFCryptoProvider &provider = SDFCryptoProvider::GetInstance(sessionPoolRound, libPath);
        unsigned int code = provider.Hash(nullptr, SM3, hsm::sdfFromHex((char *) message).data(),
                                          hsm::getHexByteLen((char *) message), hashResult.data(), &len);
        if (code != SDR_OK) {
            std::cout << "Hash failed" << std::endl;
        }
    }
}


int main(int argc, const char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " [sessionPoolSize] [loopRound]" << std::endl;
        return 1;
    }

    // Crypto provider 测试
    std::cout << "**************Begin Test, bash test-sdf-crypto [sessionPoolSize] "
                 "[loopRound]************************"
              << std::endl;
    size_t sessionPoolRound = atoi(argv[1]);
    size_t loopRound = atoi(argv[2]);
    const std::string libPath = "/usr/lib64/libswsds.so";

    std::cout << "****Verify Test****" << std::endl;
    //SDFCryptoResult result = Hash(libPath, nullptr, SM3, sdfToHex(bHashVector));
    SDFCryptoResult result = KeyGen(libPath, SM2);
    SDFCryptoResult signResult = Sign(libPath, result.privateKey, SM2, sdfToHex(bHashStdResultVector));

    Key key = Key();
    std::vector<byte> pk = sdfFromHex((char *) result.publicKey);
    std::shared_ptr<const std::vector<byte>> pubKey =
            std::make_shared<const std::vector<byte>>((byte *) pk.data(), (byte *) pk.data() + 64);
    key.setPublicKey(pubKey);


    std::vector<std::thread> verifyThread;
    auto startTime = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < sessionPoolRound; i++) {
        verifyThread.push_back(std::thread([&]() { // 使用 [&] 捕获引用
            verify(loopRound, key, signResult.signature, libPath, sessionPoolRound);
        }));
    }

    for (auto &thread: verifyThread) {
        thread.join();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    // 计算 TPS
    double totalTransactions = static_cast<double>(loopRound * sessionPoolRound);
    double tps = totalTransactions / elapsed.count();

    std::cout << "Verify test finished." << std::endl;
    std::cout << "Total Transactions: " << totalTransactions << std::endl;
    std::cout << "Elapsed Time: " << elapsed.count() << " seconds" << std::endl;
    std::cout << "TPS: " << tps << std::endl;

    // hash test
    std::cout << "****Hash Test****" << std::endl;
    std::vector<std::thread> HashThread;
    auto startTimeHash = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < sessionPoolRound; i++) {
        HashThread.push_back(std::thread([&]() {
            hash(loopRound, sessionPoolRound, sdfToHex(bHashVector), libPath);
        }));
    }

    for (auto &thread: HashThread) {
        thread.join();
    }
    auto endTimeHash = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedHash = endTimeHash - startTimeHash;

    // 计算 TPS
    double totalTransactionsHash = static_cast<double>(loopRound * sessionPoolRound);
    double tpsHash = totalTransactionsHash / elapsedHash.count();

    std::cout << "Hash test finished." << std::endl;
    std::cout << "Total Transactions: " << totalTransactionsHash << std::endl;
    std::cout << "Elapsed Time: " << elapsedHash.count() << " seconds" << std::endl;
    std::cout << "TPS: " << tpsHash << std::endl;
    return 0;
}
