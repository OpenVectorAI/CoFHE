#include <iostream>
#include <memory>
#include <string>
#include <chrono>

#include "node/network_details.hpp"
#include "node/nodes.hpp"
#include "node/client_node.hpp"
#include "node/compute_request_handler.hpp"

#define MALLOC_CHECK_ 3

using namespace CoFHE;
int main(int argc, char const *argv[])
{
    if (argc != 6 && argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " node_type[setup_node, cofhe_node, compute_node, client_node] self_node_ip self_node_port setup_node_ip setup_node_port" << std::endl;
        return 1;
    }
    std::string node_type = argv[1];
    if (node_type != "setup_node" && argc == 4)
    {
        std::cerr << "Usage: " << argv[0] << " node_type[setup_node, cofhe_node, compute_node, client_node] self_node_ip self_node_port setup_node_ip setup_node_port" << std::endl;
        return 1;
    }
    if (node_type == "setup_node")
    {
        auto self_details = NodeDetails{argv[2], argv[3], NodeType::SETUP_NODE};
        CryptoSystemDetails cs_details{
            CryptoSystemType::CoFHE_CPU,
            "public_key",
            128,
            64,
            2,
            3};
        auto setup_node = make_setup_node<CPUCryptoSystem>(self_details, cs_details);
        setup_node.run();
    }
    else if (node_type == "cofhe_node")
    {
        auto self_details = NodeDetails{argv[2], argv[3], NodeType::CoFHE_NODE};
        auto setup_node_details = NodeDetails{argv[4], argv[5], NodeType::SETUP_NODE};
        auto cofhe_node = make_cofhe_node<CPUCryptoSystem>(self_details, setup_node_details);
        cofhe_node.run();
    }
    else if (node_type == "compute_node")
    {
        auto self_details = NodeDetails{argv[2], argv[3], NodeType::COMPUTE_NODE};
        auto setup_node_details = NodeDetails{argv[4], argv[5], NodeType::SETUP_NODE};
        auto compute_node = make_compute_node<CPUCryptoSystem>(self_details, setup_node_details);
        compute_node.run();
    }
    else if (node_type == "client_node")
    {
        auto self_details = NodeDetails{argv[2], argv[3], NodeType::CLIENT_NODE};
        auto setup_node_details = NodeDetails{argv[4], argv[5], NodeType::SETUP_NODE};
        auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
        auto cs = client_node.crypto_system();
        // ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::ADD, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::PLAINTEXT, cs.serialize_plaintext(cs.make_plaintext(230))), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::PLAINTEXT, cs.serialize_plaintext(cs.make_plaintext(20)))}));
        // ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext(cs.encrypt(client_node.network_public_key(), cs.make_plaintext(230)))), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext(cs.encrypt(client_node.network_public_key(), cs.make_plaintext(20))))}));
        size_t n=8,m=8,p=8;
        Tensor<CPUCryptoSystem::PlainText*> pt1(n,m,nullptr),pt2(m,p,nullptr);
        pt1.flatten();
        pt2.flatten();
        for (size_t i = 0; i < n*m; i++)
        {
            pt1.at(i) = new CPUCryptoSystem::PlainText{cs.make_plaintext(i)};
        }
        for (size_t i = 0; i < m*p; i++)
        {
            pt2.at(i) = new CPUCryptoSystem::PlainText{cs.make_plaintext(i)};
        }
        pt1.reshape({n,m});
        pt2.reshape({m,p});
        auto ct1 = cs.encrypt_tensor(client_node.network_public_key(), pt1);
        auto ct2 = cs.encrypt_tensor(client_node.network_public_key(), pt2);
        auto start = std::chrono::high_resolution_clock::now();
        ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct2))}));
        ComputeResponse *res;
        client_node.compute(req, &res);
        auto stop = std::chrono::high_resolution_clock::now();
        // ComputeRequest req_d(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, res->data())}));
        ComputeRequest req_d(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, res->data())}));
        client_node.compute(req_d, &res);
        auto stop_d = std::chrono::high_resolution_clock::now();
        auto print = [&cs](CPUCryptoSystem::PlainText*& pt) noexcept{
            std::cout << *pt << " ";
        };
        cs.deserialize_plaintext_tensor(res->data()).walk(print);
        // std::cout<<cs.get_float_from_plaintext(cs.deserialize_plaintext(res->data()))<<std::endl;
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        auto duration_d = std::chrono::duration_cast<std::chrono::microseconds>(stop_d - stop);
        std::cout << "Time taken by function mul: "
                  << duration.count() << " microseconds" << std::endl;
        std::cout << "Time taken by function dec: "
                    << duration_d.count() << " microseconds" << std::endl;
        // CoFHENodeRequest req_p(CoFHENodeRequest::RequestType::PartialDecryption, PartialDecryptionRequest(PartialDecryptionRequest::DataType::SINGLE, (*req)->data()).to_string());
        // CoFHENodeResponse **res_p;
        // client_node.decrypt(req_p, res_p);
        // std::cout << (*res_p)->data() << std::endl;
    }
    else
    {
        std::cerr << "Invalid node type" << std::endl;
        return 1;
    }
    return 0;
}
// g++ -std=c++20 -g -ggdb  -I ../include/node/ ../include/node/test.cpp -pthread -lssl -lcrypto -o network
// openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
// ./node "setup_node" "127.0.0.1" "4455"
// ./node "cofhe_node" "127.0.0.1" "4456" "127.0.0.1" "4455"
// ./node "cofhe_node" "127.0.0.1" "4457" "127.0.0.1" "4455"
// ./node "cofhe_node" "127.0.0.1" "4458" "127.0.0.1" "4455"
// ./node "compute_node" "127.0.0.1" "4459" "127.0.0.1" "4455"
// ./node "client_node" "127.0.0.1" "4456" "127.0.0.1" "4455"
