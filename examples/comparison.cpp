#include <chrono>
#include <iostream>
#include <random>

#include "cofhe.hpp"

#define NUM_ITRS 2 //10

using namespace CoFHE;
using namespace CoFHE::binary_scheme;


void test_and(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num1 = std::rand() % 1000;
        unsigned int num2 = std::rand() % 1000;
        auto ct1 = encrypt_bitwise(cs, pk, num1);
        auto ct2 = encrypt_bitwise(cs, pk, num2);
        auto res = homomorphic_and(client_node, ct1, ct2);
        std::cout << "AND of " << num1 << " and " << num2
        << ": plaintext = " << (num1 & num2)
        << ", homomorphic = " << decrypt_bitwise(client_node, res)
        << std::endl;
    }
}

void test_or(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num1 = std::rand() % 1000;
        unsigned int num2 = std::rand() % 1000;
        auto ct1 = encrypt_bitwise(cs, pk, num1);
        auto ct2 = encrypt_bitwise(cs, pk, num2);
        auto res = homomorphic_or(client_node, ct1, ct2);
        std::cout << "OR of " << num1 << " and " << num2
                  << ": plaintext = " << (num1 | num2)
                  << ", homomorphic = " << decrypt_bitwise(client_node, res)
                  << std::endl;
    }
}

void test_not(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num = std::rand() % 1000;
        auto ct = encrypt_bitwise(cs, pk, num);
        auto res = homomorphic_not(client_node, ct);
        std::cout << "NOT of " << num
                  << ": plaintext = " << (~num)
                  << ", homomorphic = " << decrypt_bitwise(client_node, res)
                  << std::endl;
    }
}

void test_add(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num1 = std::rand() % 1000;
        unsigned int num2 = std::rand() % 1000;
        auto ct1 = encrypt_bitwise(cs, pk, num1);
        auto ct2 = encrypt_bitwise(cs, pk, num2);
        auto res = homomorphic_add(client_node, ct1, ct2);
        std::cout << "Addition of " << num1 << " and " << num2
                  << ": plaintext = " << (num1 + num2)
                  << ", homomorphic = " << decrypt_bitwise(client_node, res)
                  << std::endl;
    }
}

void test_sub(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num1 = std::rand() % 1000;
        unsigned int num2 = std::rand() % 1000;
        num1+=num2;
        auto ct1 = encrypt_bitwise(cs, pk, num1);
        auto ct2 = encrypt_bitwise(cs, pk, num2);
        auto res = homomorphic_sub(client_node, ct1, ct2);
        std::cout << "Subtraction of " << num1 << " and " << num2
                  << ": plaintext = " << (num1 - num2)
                  << ", homomorphic = " << decrypt_bitwise(client_node, res)
                  << std::endl;
    }
}

void test_gt(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        unsigned int num1 = std::rand() % 1000;
        unsigned int num2 = std::rand() % 1000;
        auto ct1 = encrypt_bitwise(cs, pk, num1);
        auto ct2 = encrypt_bitwise(cs, pk, num2);
        auto res = homomorphic_gt(client_node, ct1, ct2);
        std::cout << "Comparison(gt) of " << num1 << " and " << num2
                  << ": plaintext = " << (num1 > num2)
                  << ", homomorphic = " << decrypt_bit(client_node, res)
                  << std::endl;
    }
}

void test_serialization(ClientNode<CPUCryptoSystem>& client_node) {
    auto& cs = client_node.crypto_system();
    uint32_t num = std::rand() % 1000;
    auto ct = encrypt_bitwise(cs, client_node.network_public_key(), num);
    auto ser_ct = serialize_bitwise(cs, ct);
    auto deser_ct = deserialize_bitwise(cs, ser_ct);
    auto decrypted_num = decrypt_bitwise(client_node, deser_ct);
    std::cout << "Serialization test: " << num << " -> " << decrypted_num
              << std::endl;
}


void test(ClientNode<CPUCryptoSystem>& client_node) {
    test_and(client_node);
    test_or(client_node);
    test_not(client_node);
    test_add(client_node);
    test_sub(client_node);
    test_gt(client_node);
    test_serialization(client_node);
}

int main(int argc, char* argv[]) {
    std::srand(std::time(nullptr));
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <client_ip> <client_port> <setup_ip> <setup_port>"
                  << std::endl;
        return 1;
    }

    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details =
        NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    test(client_node);
    return 0;
}