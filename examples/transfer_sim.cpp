#include <chrono>
#include <iostream>
#include <random>

#include "cofhe.hpp"

#define NUM_ITRS 100

using namespace CoFHE;

using CipherText = CPUCryptoSystem::CipherText;
using PlainText = CPUCryptoSystem::PlainText;
using PublicKey = CPUCryptoSystem::PublicKey;
template <typename T> using vector = std::vector<T>;
template <typename T, typename U> using pair = std::pair<T, U>;

inline CipherText encrypt(CPUCryptoSystem& cs, PublicKey& pk, uint64_t num) {
    return cs.encrypt(pk, cs.make_plaintext(num));
}

inline CipherText add(ClientNode<CPUCryptoSystem>& client_node, CipherText& ct1,
                      CipherText& ct2) {
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1, ct2);
}

inline CipherText sub(ClientNode<CPUCryptoSystem>& client_node, CipherText& ct1,
                      CipherText& ct2) {
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1,
        client_node.crypto_system().negate_ciphertext(
            client_node.network_public_key(), ct2));
}

float gteq_and_decrypt(ClientNode<CPUCryptoSystem>& client_node,
                       CipherText& ct1, CipherText& ct2) {
    std::string serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext(ct1);
    std::string serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::GTEQ, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res = nullptr;
    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(res->status()) << std::endl;
        if (res) {
            std::cerr << "Error message: " << res->data() << std::endl;
        }
        delete res;
        std::exit(1);
    }

    ComputeRequest::ComputeOperationOperand decrypt_operand(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, res->data());
    delete res;

    ComputeRequest::ComputeOperationInstance decrypt_operation(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT, {decrypt_operand});

    ComputeRequest decrypt_req(decrypt_operation);
    ComputeResponse* decrypt_res = nullptr;

    client_node.compute(decrypt_req, &decrypt_res);

    if (!decrypt_res || decrypt_res->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(decrypt_res->status())
                  << std::endl;
        if (decrypt_res) {
            std::cerr << "Error message: " << decrypt_res->data() << std::endl;
        }
        delete decrypt_res;
        std::exit(1);
    }

    auto decrypted_result =
        client_node.crypto_system().get_float_from_plaintext(
            client_node.crypto_system().deserialize_plaintext(
                decrypt_res->data()));
    delete decrypt_res;
    return decrypted_result;
}

vector<pair<CipherText, CipherText>>
generate_random_test_pairs(CPUCryptoSystem& cs, PublicKey& pk) {
    vector<pair<CipherText, CipherText>> pairs;
    for (int i = 0; i < NUM_ITRS; i++) {
        uint64_t num1 = std::rand() % 1000;
        uint64_t num2 = std::rand() % 1000;
        pairs.push_back({encrypt(cs, pk, num1), encrypt(cs, pk, num2)});
    }
    return pairs;
}

void simulate_transfer(ClientNode<CPUCryptoSystem>& client_node) {
    // a transfer is described as below:
    // require(balances[msg.sender] >= amount);
    // balances[msg.sender] -= amount;
    // balances[recipient] += amount;
    // Simulating this by performing 1 comparison, 1 addition, 1 subtraction and
    // 1 decryption Can Use speculative execution to perform the operations with
    // less latency(uses OpenMP)
    auto test_balances_and_send_amount = generate_random_test_pairs(
        client_node.crypto_system(), client_node.network_public_key());
    // doing dummy OpenMP parallel for, for preventing cold start
    //     int dummyVar = 0;
    // #pragma omp parallel for
    //     for (int i = 0; i < (1 << 20); i++) {
    //         dummyVar++;
    //     }
    // std::cout << "DummyVar: " << dummyVar << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_ITRS; i++) {
        // #pragma omp sections
        {
            // #pragma omp section
            {
                auto comparison_res = gteq_and_decrypt(
                    client_node, test_balances_and_send_amount[i].first,
                    test_balances_and_send_amount[i].second);
                bool allowed = comparison_res > 0;
                if (!allowed) {
                    // throw std::runtime_error("Insufficient balance.");
                    // std::cout << "Insufficient balance." << std::endl;
                } else {
                    // std::cout << "Sufficient balance." << std::endl;
                }
            }
            // #pragma omp section
            {
                auto s_new_balance =
                    sub(client_node, test_balances_and_send_amount[i].first,
                        test_balances_and_send_amount[i].second);
            }
            // #pragma omp section
            {
                auto r_new_balance =
                    add(client_node, test_balances_and_send_amount[i].first,
                        test_balances_and_send_amount[i].second);
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Time taken for " << NUM_ITRS << " iterations: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << "ms" << std::endl;
    std::cout << "TPS: "
              << (NUM_ITRS * 1000.0) /
                     std::chrono::duration_cast<std::chrono::milliseconds>(
                         end - start)
                         .count()
              << std::endl;
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
    simulate_transfer(client_node);
    return 0;
}