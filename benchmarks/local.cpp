#include "cofhe.hpp"

#include <iostream>
#include "./benchmark.hpp"

using namespace CoFHE;


auto get_crypto_system()
{
    return make_cryptosystem(128, 128, Device::CPU);
}

template <typename CryptoSystem>
auto get_keys(CryptoSystem &cs)
{
    auto sk = cs.keygen();
    auto pk = cs.keygen(sk);
    return std::make_pair(sk, pk);
}

void benchmark_encrypt_decrypt()
{
    auto cs = get_crypto_system();
    auto [sk, pk] = get_keys(cs);
    // std::vector<size_t> n = {8, 16, 32, 64, 128, 256, 512, 1024};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {64};
    std::vector<size_t> m = {64};
    Benchmark b("encrypt_decrypt");
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            Tensor<CPUCryptoSystem::PlainText *> pts(ni, mi, nullptr);
            for (size_t i = 0; i < ni * mi; i++)
            {
                pts.at(i) = new CPUCryptoSystem::PlainText(cs.make_plaintext(i + 1));
            }
            pts.reshape({ni, mi});
            auto encrypt_decrypt = [&cs, &pk, &pts, &sk]()
            {
                auto ct = cs.encrypt_tensor(pk, pts);
                auto res = cs.decrypt_tensor(sk, ct);
                ct.flatten();
                res.flatten();
                for (size_t i = 0; i < ct.num_elements(); i++)
                {
                    delete res.at(i);
                    delete ct.at(i);
                }
            };
            b.run(encrypt_decrypt,1);
            pts.flatten();
            for (size_t i = 0; i < ni * mi; i++)
            {
                delete pts.at(i);
            }
            std::cout << "n: " << ni << " m: " << mi << std::endl;
        }
    }
    b.print_summary();
}

void benchmark_ciphertext_matadd()
{
    auto cs = get_crypto_system();
    using CryptoSystem = decltype(cs);
    auto [sk, pk] = get_keys(cs);
    // std::vector<size_t> n = {8, 16, 32, 64, 128, 256, 512, 1024};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {64};
    std::vector<size_t> m = {64};
    std::vector<size_t> p = {64};
    Benchmark b("ciphertext_matadd");
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
                auto matadd = [&cs, &pk, &ct1, &ct2]()
                {
                    auto res = cs.add_ciphertext_tensors(pk, ct1, ct2);
                    for (int i = 0; i < 49; ++i)
                    {
                        auto res_c = cs.add_ciphertext_tensors(pk, res, ct2);
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

void benchmark_scal_matmul()
{
    auto cs = get_crypto_system();
    using CryptoSystem = decltype(cs);
    auto [sk, pk] = get_keys(cs);
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {8};
    std::vector<size_t> m = {64};
    std::vector<size_t> p = {64};
    Benchmark b("scal_matmul");
    float min_time_ratio_with_mi_pi = std::numeric_limits<float>::max();
    size_t min_pi = 0, min_mi = 0;
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
                auto scal_matmul = [&cs, &pk, &pt2, &ct1]()
                {
                    auto res = cs.scal_ciphertext_tensors(pk, pt2, ct1);
                    for (int i = 0; i < 49; ++i)
                    {
                        auto res_c = cs.scal_ciphertext_tensors(pk, pt2, res);
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

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <benchmark>" << std::endl;
        return EXIT_FAILURE;
    }
    std::string benchmark = argv[1];
    if (benchmark == "encrypt_decrypt")
    {
        benchmark_encrypt_decrypt();
    }
    else if (benchmark == "scal_matmul")
    {
        benchmark_scal_matmul();
    }
    else if (benchmark == "ciphertext_matadd")
    {
        benchmark_ciphertext_matadd();
    }
    else
    {
        std::cerr << "Unknown benchmark: " << benchmark << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}