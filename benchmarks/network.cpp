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
    using CryptoSystem = CPUCryptoSystem;
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {8};
    std::vector<size_t> m = {64};
    std::vector<size_t> p = {64};
    Benchmark b("ciphertext_matmul");
    auto cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CryptoSystem::PlainText *> pt1(ni, mi, nullptr);
                pt1.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    pt1.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                Tensor<CryptoSystem::PlainText *> pt2(mi, pi, nullptr);
                pt2.flatten();
                for (size_t i = 0; i < mi * pi; i++)
                {
                    pt2.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                pt1.reshape({ni, mi});
                pt2.reshape({mi, pi});
                auto ct1 = cs.encrypt_tensor(pk, pt1);
                auto ct2 = cs.encrypt_tensor(pk, pt2);
                auto matmul = [&client_node, &ct1, &ct2, &cs]()
                {
                    ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct2))}));
                    ComputeResponse *res_;
                    client_node.compute(req, &res_);
                    auto res = cs.deserialize_ciphertext_tensor(res_->data());
                    delete res_;
                    for (size_t i = 0; i < 49; i++)
                    {
                        ComputeRequest req_c = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(res)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct2))}));
                        ComputeResponse *res_c_;
                        client_node.compute(req_c, &res_c_);
                        auto res_c = cs.deserialize_ciphertext_tensor(res_c_->data());
                        delete res_c_;
                        res.flatten();
                        for (size_t i = 0; i < res.num_elements(); i++)
                        {
                            delete res.at(i);
                        }
                        res = res_c;
                        std::cout << "Iteration: " << i << std::endl;
                    }
                    res.flatten();
                    for (size_t i = 0; i < res.num_elements(); i++)
                    {
                        delete res.at(i);
                    } 
                };
                b.run(matmul, 1);
                pt1.flatten();
                pt2.flatten();
                ct1.flatten();
                ct2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete pt1.at(i);
                    delete ct1.at(i);
                }
                for (size_t i = 0; i < mi * pi; i++)
                {
                    delete pt2.at(i);
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
    using CryptoSystem = CPUCryptoSystem;
    std::vector<size_t> n = {8};
    std::vector<size_t> m = {64};
    std::vector<size_t> p = {64};
    Benchmark b("scalar_ciphertext_matmul");
    auto cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CryptoSystem::PlainText *> pt1(ni, mi, nullptr);
                pt1.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    pt1.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                pt1.reshape({ni, mi});
                auto ct1 = cs.encrypt_tensor(pk, pt1);
                Tensor<CryptoSystem::PlainText *> pt2(mi, pi, nullptr);
                pt2.flatten();
                for (size_t i = 0; i < mi * pi; i++)
                {
                    pt2.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                ct1.reshape({ni, mi});
                pt2.reshape({mi, pi});
                auto scal_matmul = [&client_node, &pt2, &ct1, &cs]()
                {
                    ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::PLAINTEXT, cs.serialize_plaintext_tensor(pt2))}));
                    ComputeResponse *res_;
                    client_node.compute(req, &res_);
                    auto res = cs.deserialize_ciphertext_tensor(res_->data());
                    delete res_;
                    for (size_t i = 0; i < 49; i++)
                    {
                        ComputeRequest req_c = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(res)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::PLAINTEXT, cs.serialize_plaintext_tensor(pt2))}));
                        ComputeResponse *res_c_;
                        client_node.compute(req_c, &res_c_);
                        auto res_c = cs.deserialize_ciphertext_tensor(res_c_->data());
                        delete res_c_;
                        res.flatten();
                        for (size_t i = 0; i < res.num_elements(); i++)
                        {
                            delete res.at(i);
                        }
                        res = res_c;
                    }
                    res.flatten();
                    for (size_t i = 0; i < res.num_elements(); i++)
                    {
                        delete res.at(i);
                    }
                };
                b.run(scal_matmul, 1);
                pt1.flatten();
                ct1.flatten();
                pt2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete pt1.at(i);
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

    using CryptoSystem = CPUCryptoSystem;
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {64};
    std::vector<size_t> m = {64};
    std::vector<size_t> p = {64};
    Benchmark b("ciphertext_matadd");
    auto cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CryptoSystem::PlainText *> pt1(ni, mi, nullptr);
                pt1.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    pt1.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                Tensor<CryptoSystem::PlainText *> pt2(mi, pi, nullptr);
                pt2.flatten();
                for (size_t i = 0; i < mi * pi; i++)
                {
                    pt2.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                pt1.reshape({ni, mi});
                pt2.reshape({mi, pi});
                auto ct1 = cs.encrypt_tensor(pk, pt1);
                auto ct2 = cs.encrypt_tensor(pk, pt2);
                auto matadd = [&client_node, &ct1, &ct2, &cs]()
                {
                    ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::ADD, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct1)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct2))}));
                    ComputeResponse *res_;
                    client_node.compute(req, &res_);
                    auto res = cs.deserialize_ciphertext_tensor(res_->data());
                    delete res_;
                    for (size_t i = 0; i < 49; i++)
                    {
                        ComputeRequest req_c = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::ADD, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(res)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct2))}));
                        ComputeResponse *res_c_;
                        client_node.compute(req_c, &res_c_);
                        auto res_c = cs.deserialize_ciphertext_tensor(res_c_->data());
                        delete res_c_;
                        res.flatten();
                        for (size_t i = 0; i < res.num_elements(); i++)
                        {
                            delete res.at(i);
                        }
                        res = res_c;
                    }
                    res.flatten();
                    for (size_t i = 0; i < res.num_elements(); i++)
                    {
                        delete res.at(i);
                    }
                };
                b.run(matadd, 1);
                pt1.flatten();
                pt2.flatten();
                ct1.flatten();
                ct2.flatten();
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete pt1.at(i);
                    delete ct1.at(i);
                }
                for (size_t i = 0; i < ni * mi; i++)
                {
                    delete pt2.at(i);
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
    std::vector<size_t> n = {64};
    std::vector<size_t> m = {64};
    Benchmark b("decrypt");
    auto cs = client_node.crypto_system();
    auto pk = client_node.network_public_key();
    for (auto ni : n)
    {
        for (auto mi : m)
        {

            Tensor<CPUCryptoSystem::PlainText *> pt1(ni, mi, nullptr);
            pt1.flatten();
            for (size_t i = 0; i < ni * mi; i++)
            {
                pt1.at(i) = new CPUCryptoSystem::PlainText(cs.make_plaintext(i + 1));
            }
            pt1.reshape({ni, mi});
            auto ct1 = cs.encrypt_tensor(pk, pt1);
            auto decrypt = [&client_node, &ct1, &cs]()
            {
                ComputeRequest req = ComputeRequest(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(ct1))}));
                ComputeResponse *res_;
                client_node.compute(req, &res_);
                auto res = cs.deserialize_plaintext_tensor(res_->data());
                delete res_;
                res.flatten();
                for (size_t i = 0; i < res.num_elements(); i++)
                {
                    delete res.at(i);
                }
            };
            b.run(decrypt, 1);
            pt1.flatten();
            ct1.flatten();
            for (size_t i = 0; i < ni * mi; i++)
            {
                delete pt1.at(i);
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