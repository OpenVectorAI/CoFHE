#include <chrono>
#include <iostream>

#include "cofhe.hpp"

using namespace CoFHE;

#define NUM_ITRS 10

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <client_ip> <client_port> <setup_ip> <setup_port>"
                  << std::endl;
        return 1;
    }

    std::srand(std::time(nullptr));

    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details =
        NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    auto& cs = client_node.crypto_system();
    auto& pk = client_node.network_public_key();
    for (int i = 0; i < NUM_ITRS; i++) {
        auto num1 = std::rand() % 10000000000;
        auto num2 = std::rand() % 10000000000;

        auto pt1 = cs.make_plaintext(num1);
        auto pt2 = cs.make_plaintext(num2);

        auto ct1 = cs.encrypt(pk, pt1);
        auto ct2 = cs.encrypt(pk, pt2);

        std::string serialized_ct1 = cs.serialize_ciphertext(ct1);
        std::string serialized_ct2 = cs.serialize_ciphertext(ct2);

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
        auto start = std::chrono::high_resolution_clock::now();
        client_node.compute(req, &res);
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        std::cout << "Elapsed time: " << elapsed.count() << " seconds"
                  << std::endl;

        if (!res || res->status() != ComputeResponse::Status::OK) {
            std::cerr << "Error: " << static_cast<int>(res->status())
                      << std::endl;
            if (res) {
                std::cerr << "Error message: " << res->data() << std::endl;
            }
            delete res;
            return 1;
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

        if (!decrypt_res ||
            decrypt_res->status() != ComputeResponse::Status::OK) {
            std::cerr << "Error: " << static_cast<int>(decrypt_res->status())
                      << std::endl;
            if (decrypt_res) {
                std::cerr << "Error message: " << decrypt_res->data()
                          << std::endl;
            }
            delete decrypt_res;
            return 1;
        }

        auto decrypted_result = cs.get_float_from_plaintext(
            cs.deserialize_plaintext(decrypt_res->data()));
        std::cout << "Decrypted result: " << decrypted_result << std::endl;
        std::cout << "Original numbers: " << num1 << " and " << num2
                  << std::endl;
        std::cout << "Comparison result: " << (num1 >= num2 ? "True" : "False")
                  << std::endl;
        std::cout << "Decrypted comparison result: "
                  << (decrypted_result > 0 ? "True" : "False") << std::endl;
        if ((decrypted_result > 0) != (num1 >= num2)) {
            std::cerr << "Decrypted comparison result does not match original"
                      << std::endl;
            delete decrypt_res;
            return 1;
        }
        delete decrypt_res;
    }

    std::cout << "======================" << std::endl;
    size_t n = 20, m = 20;
    Tensor<CPUCryptoSystem::PlainText*> pt1_tensor(n, m, nullptr),
        pt2_tensor(n, m, nullptr);
    pt1_tensor.flatten();
    pt2_tensor.flatten();
    for (size_t i = 0; i < pt1_tensor.size(); i++) {
        pt1_tensor[i] = new CPUCryptoSystem::PlainText(
            cs.make_plaintext(std::rand() % 10000000000));
        pt2_tensor[i] = new CPUCryptoSystem::PlainText(
            cs.make_plaintext(std::rand() % 10000000000));
    }
    pt1_tensor.reshape({n, m});
    pt2_tensor.reshape({n, m});
    auto ct1_tensor = cs.encrypt_tensor(pk, pt1_tensor);
    auto ct2_tensor = cs.encrypt_tensor(pk, pt2_tensor);

    std::string serialized_ct1_tensor =
        cs.serialize_ciphertext_tensor(ct1_tensor);
    std::string serialized_ct2_tensor =
        cs.serialize_ciphertext_tensor(ct2_tensor);
    ComputeRequest::ComputeOperationOperand operand1_tensor(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1_tensor);
    ComputeRequest::ComputeOperationOperand operand2_tensor(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2_tensor);
    ComputeRequest::ComputeOperationInstance operation_tensor(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::GTEQ,
        {operand1_tensor, operand2_tensor});
    ComputeRequest req_tensor(operation_tensor);
    ComputeResponse* res_tensor = nullptr;
    auto start_tensor = std::chrono::high_resolution_clock::now();
    client_node.compute(req_tensor, &res_tensor);
    auto end_tensor = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_tensor = end_tensor - start_tensor;
    std::cout << "Elapsed time: " << elapsed_tensor.count() << " seconds"
              << std::endl;

    if (!res_tensor || res_tensor->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(res_tensor->status())
                  << std::endl;
        if (res_tensor) {
            std::cerr << "Error message: " << res_tensor->data() << std::endl;
        }
        delete res_tensor;
        return 1;
    }

    ComputeRequest::ComputeOperationOperand decrypt_operand_tensor(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, res_tensor->data());
    delete res_tensor;
    ComputeRequest::ComputeOperationInstance decrypt_operation_tensor(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT, {decrypt_operand_tensor});
    ComputeRequest decrypt_req_tensor(decrypt_operation_tensor);
    ComputeResponse* decrypt_res_tensor = nullptr;
    client_node.compute(decrypt_req_tensor, &decrypt_res_tensor);
    if (!decrypt_res_tensor ||
        decrypt_res_tensor->status() != ComputeResponse::Status::OK) {
        std::cerr << "Error: " << static_cast<int>(decrypt_res_tensor->status())
                  << std::endl;
        if (decrypt_res_tensor) {
            std::cerr << "Error message: " << decrypt_res_tensor->data()
                      << std::endl;
        }
        delete decrypt_res_tensor;
        return 1;
    }
    auto decrypted_result_tensor =
        cs.deserialize_plaintext_tensor(decrypt_res_tensor->data());
    decrypted_result_tensor.flatten();
    pt1_tensor.flatten();
    pt2_tensor.flatten();
    for (size_t i = 0; i < decrypted_result_tensor.size(); i++) {
        int num1 = cs.get_float_from_plaintext(*pt1_tensor[i]);
        int num2 = cs.get_float_from_plaintext(*pt2_tensor[i]);
        std::cout << "Decrypted result: "
                  << cs.get_float_from_plaintext(*decrypted_result_tensor[i])
                  << std::endl;
        std::cout << "Original numbers: " << num1 << " and " << num2
                  << std::endl;
        std::cout << "Comparison result: " << (num1 >= num2 ? "True" : "False")
                  << std::endl;
        std::cout << "Decrypted comparison result: "
                  << (cs.get_float_from_plaintext(*decrypted_result_tensor[i]) >
                              0
                          ? "True"
                          : "False")
                  << std::endl;
        if ((cs.get_float_from_plaintext(*decrypted_result_tensor[i]) > 0) !=
            (num1 >= num2)) {
            std::cerr << "Error: Decrypted result does not match original "
                         "numbers"
                      << std::endl;
            break;
        }
    }
    ct1_tensor.flatten();
    ct2_tensor.flatten();
    for (size_t i = 0; i < pt1_tensor.size(); i++) {
        delete pt1_tensor[i];
        delete pt2_tensor[i];
        delete ct1_tensor[i];
        delete ct2_tensor[i];
        delete decrypted_result_tensor[i];
    }
    delete decrypt_res_tensor;

    return 0;
}