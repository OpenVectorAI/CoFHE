#include <iostream>

#include "cofhe.hpp"
#include "node/network_details.hpp"
#include "node/client_node.hpp"
#include "node/compute_request_handler.hpp"

#include "./benchmark.hpp"

using namespace CoFHE;

auto get_client_node(std::string setup_node_ip, std::string setup_node_port)
{
    auto setup_node_details = NodeDetails{setup_node_ip, setup_node_port, NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    return client_node;
}

void benchmark_ciphertext_matmul(ClientNode<CPUCryptoSystem> &client_node)
{
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = { 8};
    std::vector<size_t> m = { 768};
    std::vector<size_t> p = { 768};
    Benchmark b("ciphertext_matmul");
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CPUCryptoSystem::CipherText *> ct1(ni, mi, nullptr);
                ct1.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct1.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
                }
                Tensor<CPUCryptoSystem::CipherText *> ct2(mi, pi, nullptr);
                ct2.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < mi * pi; i++)
                {
                    ct2.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
                }
                ct1.reshape({ni, mi});
                ct2.reshape({mi, pi});
                ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct2))}));
                ComputeResponse *res_;
                auto matmul = [&client_node, &ct1, &ct2, &res_, &req]()
                {
                    client_node.compute(req, &res_);
                };
                b.run(matmul, 1);
                auto res = client_node.crypto_system().deserialize_ciphertext_tensor(res_->data());
                delete res_;
                res.flatten();
                for (size_t i = 0; i < res.num_elements(); i++)
                {
                    delete res.at(i);
                }
                ct1.flatten();
                ct2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete ct1.at(i);
                }
                for (size_t i = 0; i < mi * pi; i++)
                {
                    delete ct2.at(i);
                }
                std::cout << "n: " << ni << " m: " << mi << " p: " << pi << std::endl;
            }
        }
    }
    b.print_summary();
}

void benchmark_scalar_ciphertext_matmul(ClientNode<CPUCryptoSystem> &client_node)
{
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = { 8};
    std::vector<size_t> m = { 768};
    std::vector<size_t> p = { 768};
    Benchmark b("scalar_ciphertext_matmul");
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CPUCryptoSystem::CipherText *> ct1(ni, mi, nullptr);
                ct1.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct1.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
                }
                Tensor<CPUCryptoSystem::PlainText *> pt2(mi, pi, nullptr);
                pt2.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < mi * pi; i++)
                {
                    pt2.at(i) = new CPUCryptoSystem::PlainText(client_node.crypto_system().make_plaintext(i + 1));
                }
                ct1.reshape({ni, mi});
                pt2.reshape({mi, pi});
                ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::PLAINTEXT, client_node.crypto_system().serialize_plaintext_tensor(pt2))}));
                ComputeResponse *res_;
                auto scal_matmul = [&client_node, &pt2, &ct1, &res_, &req]()
                {
                    client_node.compute(req, &res_);
                };
                b.run(scal_matmul, 1);
                auto res = client_node.crypto_system().deserialize_ciphertext_tensor(res_->data());
                delete res_;
                res.flatten();
                for (size_t i = 0; i < res.num_elements(); i++)
                {
                    delete res.at(i);
                }
                ct1.flatten();
                pt2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete ct1.at(i);
                }
                for (size_t i = 0; i < mi * pi; i++)
                {
                    delete pt2.at(i);
                }
                std::cout << "n: " << ni << " m: " << mi << " p: " << pi << std::endl;
            }
        }
    }
    b.print_summary();
}

void benchmark_ciphertext_matadd(ClientNode<CPUCryptoSystem> &client_node)
{
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = { 768};
    std::vector<size_t> m = { 768};
    std::vector<size_t> p = { 768};
    Benchmark b("ciphertext_matadd");
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CPUCryptoSystem::CipherText *> ct1(ni, mi, nullptr);
                ct1.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct1.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
                }
                Tensor<CPUCryptoSystem::CipherText *> ct2(ni, mi, nullptr);
                ct2.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct2.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
                }
                ct1.reshape({ni, mi});
                ct2.reshape({ni, mi});
                ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::ADD, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct2))}));
                ComputeResponse *res_;
                auto matadd = [&client_node, &ct1, &ct2, &res_, &req]()
                {
                    client_node.compute(req, &res_);
                };
                b.run(matadd, 1);
                auto res = client_node.crypto_system().deserialize_ciphertext_tensor(res_->data());
                delete res_;
                res.flatten();
                for (size_t i = 0; i < res.num_elements(); i++)
                {
                    delete res.at(i);
                }
                ct1.flatten();
                ct2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete ct1.at(i);
                }
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete ct2.at(i);
                }
                std::cout << "n: " << ni << " m: " << mi << " p: " << pi << std::endl;
            }
        }
    }
    b.print_summary();
}

void benchmark_decrypt(ClientNode<CPUCryptoSystem> &client_node)
{
    // std::vector<size_t> n = {8, 16, 32, 64, 128, 256, 512, 1024};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = { 8};
    std::vector<size_t> m = { 768};
    Benchmark b("decrypt");
    for (auto ni : n)
    {
        for (auto mi : m)
        {

            Tensor<CPUCryptoSystem::CipherText *> ct1(ni, mi, nullptr);
            ct1.flatten();
#pragma omp parallel for
            for (size_t i = 0; i < ni * mi; i++)
            {
                ct1.at(i) = new CPUCryptoSystem::CipherText(client_node.crypto_system().encrypt(client_node.network_public_key(), client_node.crypto_system().make_plaintext(i + 1)));
            }
            ct1.reshape({ni, mi});
            ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node.crypto_system().serialize_ciphertext_tensor(ct1))}));
            ComputeResponse *res_;
            auto decrypt = [&client_node, &ct1, &res_, &req]()
            {
                client_node.compute(req, &res_);
            };
            b.run(decrypt, 1);
            auto res = client_node.crypto_system().deserialize_plaintext_tensor(res_->data());
            delete res_;
            res.flatten();
            for (size_t i = 0; i < res.num_elements(); i++)
            {
                delete res.at(i);
            }
            ct1.flatten();
            for (size_t i = 0; i < ni * mi; i++)
            {
                delete ct1.at(i);
            }
            std::cout << "n: " << ni << " m: " << mi << std::endl;
        }
    }
    b.print_summary();
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <benchmark>" << std::endl;
        return EXIT_FAILURE;
    }
    std::string benchmark = argv[1];
    std::string setup_node_ip = "127.0.0.1";
    std::string setup_node_port = "4455";
    if (argc >= 4)
    {
        setup_node_ip = argv[2];
        setup_node_port = argv[3];
    }
    auto client_node = get_client_node(setup_node_ip, setup_node_port);
    if (benchmark == "ciphertext_matmul")
    {
        benchmark_ciphertext_matmul(client_node);
    }
    else if (benchmark == "scalar_ciphertext_matmul")
    {
        benchmark_scalar_ciphertext_matmul(client_node);
    }
    else if (benchmark == "ciphertext_matadd")
    {
        benchmark_ciphertext_matadd(client_node);
    }
    else if (benchmark == "decrypt")
    {
        benchmark_decrypt(client_node);
    }
    else
    {
        std::cerr << "Unknown benchmark: " << benchmark << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}