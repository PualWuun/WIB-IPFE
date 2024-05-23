#include "utils/func.h"
#include <openssl/sha.h>

std::string H1(std::string &s) {
    std::string res;
    res.resize(33);
    SHA256((const unsigned char *)s.c_str(), s.length(), (unsigned char *)res.c_str());
    res[32] = 0;
    return res;
};

void Hw(element_t &C_1, element_t &C_2, element_t &C_3, ElementList *C_x_i, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    auto bytes1 = reinterpret_cast<unsigned char *>(&C_1);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    auto bytes2 = reinterpret_cast<unsigned char *>(&C_2);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    auto bytes3 = reinterpret_cast<unsigned char *>(&C_3);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    for(int i = 1; i <= C_x_i->len();i++) {
        auto bytes = reinterpret_cast<unsigned char *>(C_x_i->At(i));
        SHA256_Update(&sha256, bytes, sizeof(bytes));
    }
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
    // unsigned char buffer[65]; // 足够大的缓冲区来保存序列化后的数据

    // // 计算SHA-256哈希
    // unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // element_to_bytes(buffer, C_1);
    // SHA256_Update(&sha256, buffer, element_length_in_bytes(C_1));
    // element_to_bytes(buffer, C_2);
    // SHA256_Update(&sha256, buffer, element_length_in_bytes(C_2));
    // element_to_bytes(buffer, C_3);
    // SHA256_Update(&sha256, buffer, element_length_in_bytes(C_3));
    // for(int i = 1; i <= C_x_i->len();i++) {
    //     element_to_bytes(buffer, *C_x_i->At(i));
    //     SHA256_Update(&sha256, buffer, element_length_in_bytes(*C_x_i->At(i)));
    // }
    // SHA256_Final(hash, &sha256);
    // element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}