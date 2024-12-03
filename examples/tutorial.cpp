#include <iostream>
#include <chrono>
#include "cofhe.hpp"
#include "node/network_details.hpp"
#include "node/client_node.hpp"
#include "node/compute_request_handler.hpp"

using namespace CoFHE;

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <client_ip> <client_port> <setup_ip> <setup_port>" << std::endl;
        return 1;
    }

    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details = NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    auto& cs = client_node.crypto_system();

    // Step 3: Create tensors of encrypted data
    size_t n = 8, m = 8, p = 8;
    Tensor<CPUCryptoSystem::PlainText*> pt1(n, m, nullptr);
    pt1.flatten();
    for (size_t i = 0; i < n * m; i++) {
        pt1.at(i) = new CPUCryptoSystem::PlainText(cs.make_plaintext(i + 1));
    }

    Tensor<CPUCryptoSystem::PlainText*> pt2(m, p, nullptr);
    pt2.flatten();
    for (size_t i = 0; i < m * p; i++) {
        pt2.at(i) = new CPUCryptoSystem::PlainText(cs.make_plaintext(i + 1));
    }

    pt1.reshape({n, m});
    pt2.reshape({m, p});
    auto ct1 = cs.encrypt_tensor(client_node.network_public_key(), pt1);
    auto ct2 = cs.encrypt_tensor(client_node.network_public_key(), pt2);

    // Step 4: Serialize tensors
    std::string serialized_ct1 = cs.serialize_ciphertext_tensor(ct1);
    std::string serialized_ct2 = cs.serialize_ciphertext_tensor(ct2);

    // Step 5: Create compute request for multiplication
    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT,
        serialized_ct1
    );

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT,
        serialized_ct2
    );

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY,
        { operand1, operand2 }
    );

    ComputeRequest req(operation);

    // Step 6: Perform computation
    auto start = std::chrono::high_resolution_clock::now();
    ComputeResponse* res = nullptr;
    client_node.compute(req, &res);
    auto stop = std::chrono::high_resolution_clock::now();

    if (res && res->status() == ComputeResponse::Status::OK) {
        std::cout << "Encrypted result tensor received." << std::endl;
    } else {
        std::cerr << "Computation failed." << std::endl;
        return 1;
    }

    // Step 7: Create compute request for decryption
    ComputeRequest::ComputeOperationOperand decrypt_operand(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT,
        res->data()
    );

    ComputeRequest::ComputeOperationInstance decrypt_operation(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT,
        { decrypt_operand }
    );

    ComputeRequest req_d(decrypt_operation);

    client_node.compute(req_d, &res);
    auto stop_d = std::chrono::high_resolution_clock::now();

    if (res && res->status() == ComputeResponse::Status::OK) {
        std::cout << "Decrypted result tensor received." << std::endl;
    } else {
        std::cerr << "Decryption failed." << std::endl;
        return 1;
    }

    // Step 8: Deserialize and display the result
    Tensor<CPUCryptoSystem::PlainText*> result_tensor = cs.deserialize_plaintext_tensor(res->data());
    result_tensor.flatten();

    std::cout << "Resulting matrix after multiplication and decryption:" << std::endl;
    for (size_t idx = 0; idx < result_tensor.size(); ++idx) {
        float value = cs.get_float_from_plaintext(*result_tensor[idx]);
        std::cout << value << " ";
        if ((idx + 1) % p == 0) {
            std::cout << std::endl;
        }
    }

    // Display computation times
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    auto duration_d = std::chrono::duration_cast<std::chrono::microseconds>(stop_d - stop);

    std::cout << "Time taken by multiplication: " << duration.count() << " microseconds" << std::endl;
    std::cout << "Time taken by decryption: " << duration_d.count() << " microseconds" << std::endl;

    pt1.flatten();
    for (size_t i = 0; i < n * m; i++) {
        delete pt1.at(i);
    }
    pt2.flatten();
    for (size_t i = 0; i < m * p; i++) {
        delete pt2.at(i);
    }
    ct1.flatten();
    for (size_t i = 0; i < n * m; i++) {
        delete ct1.at(i);
    }
    ct2.flatten();
    for (size_t i = 0; i < m * p; i++) {
        delete ct2.at(i);
    }
    result_tensor.flatten();
    for (size_t i = 0; i < n * p; i++) {
        delete result_tensor.at(i);
    }

    return 0;
}