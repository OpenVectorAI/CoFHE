#include "cofhe.hpp"

#include <iostream>
#include "./benchmark.hpp"

using namespace CoFHE;

#define ENC_BATCH_SIZE 100


auto get_crypto_system()
{
    return make_cryptosystem(32, 32, Device::CPU);
}

template <typename CryptoSystem>
auto get_keys(CryptoSystem &cs)
{
    auto sk = cs.keygen();
    auto pk = cs.keygen(sk);
    return std::make_pair(sk, pk);
}

auto get_plaintext_vector(auto &cs, size_t n)
{
    std::vector<decltype(cs.make_plaintext(0.0f))> pt;
    for (size_t i = 0; i < n; i++)
    {
        pt.push_back(cs.make_plaintext(0.0f));
    }
    return pt;
}

void benchmark_encrypt_decrypt()
{
    auto cs = get_crypto_system();
    auto [sk, pk] = get_keys(cs);
    auto pts = get_plaintext_vector(cs, ENC_BATCH_SIZE);
    auto encrypter = [&cs, &pk, &pts]()
    {
        for (auto pt : pts)
        {
            cs.encrypt(pk, pt);
        }
    };
    auto decrypter = [&cs, &sk, &pk, &pts]()
    {
        for (auto pt : pts)
        {
            auto ct = cs.encrypt(pk, pt);
            cs.decrypt(sk, ct);
        }
    };
    Benchmark b("encrypt_decrypt 1000");
    b.run(encrypter, 1000);
    b.print_summary();
    b.reset();
    b.run(decrypter, 1000);
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
    std::vector<size_t> n = {768};
    std::vector<size_t> m = {768};
    std::vector<size_t> p = {768};
    Benchmark b("ciphertext_matadd");
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {
                Tensor<CryptoSystem::CipherText *> ct1(ni, mi, nullptr);
                ct1.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct1.at(i) = new CryptoSystem::CipherText(cs.encrypt(pk, cs.make_plaintext(i + 1)));
                }
                Tensor<CryptoSystem::CipherText *> ct2(mi, pi, nullptr);
                ct2.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < mi * pi; i++)
                {
                    ct2.at(i) = new CryptoSystem::CipherText(cs.encrypt(pk, cs.make_plaintext(i + 1)));
                }
                ct1.reshape({ni, mi});
                ct2.reshape({mi, pi});
                auto matadd = [&cs, &pk, &ct1, &ct2]()
                {
                    cs.add_ciphertext_tensors(pk, ct1, ct2);
                };
                b.run(matadd, 1);
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

void benchmark_scal_matmul()
{
    auto cs = get_crypto_system();
    using CryptoSystem = decltype(cs);
    auto [sk, pk] = get_keys(cs);
    // std::vector<size_t> n = {8, 16, 32, 64, 128};
    // std::vector<size_t> m = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    // std::vector<size_t> p = {32, 64, 128, 256, 512, 768, 1024, 1536, 2048};
    std::vector<size_t> n = {8};
    std::vector<size_t> m = {768};
    std::vector<size_t> p = {768};
    Benchmark b("scal_matmul");
    float min_time_ratio_with_mi_pi = std::numeric_limits<float>::max();
    size_t min_pi = 0, min_mi = 0;
    for (auto ni : n)
    {
        for (auto mi : m)
        {
            for (auto pi : p)
            {

                Tensor<CryptoSystem::CipherText *> ct1(ni, mi, nullptr);
                ct1.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < ni * mi; i++)
                {
                    ct1.at(i) = new CryptoSystem::CipherText(cs.encrypt(pk, cs.make_plaintext(i + 1)));
                }
                Tensor<CryptoSystem::PlainText *> pt2(mi, pi, nullptr);
                pt2.flatten();
#pragma omp parallel for
                for (size_t i = 0; i < mi * pi; i++)
                {
                    pt2.at(i) = new CryptoSystem::PlainText(cs.make_plaintext(i + 1));
                }
                ct1.reshape({ni, mi});
                pt2.reshape({mi, pi});
                Tensor<CryptoSystem::CipherText *> res(ni, pi, nullptr);
                auto scal_matmul = [&cs, &pk, &pt2, &ct1, &res]()
                {
                    res = cs.scal_ciphertext_tensors(pk, pt2, ct1);
                };
                b.run(scal_matmul, 1);
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
                std::cout << "n: " << ni << " m: " << mi << " p: " << pi << std::endl;
                std::cout << (b.last_run().count()) / (mi * pi) << "ms" << std::endl;
                if ((b.last_run().count()) / (mi) < min_time_ratio_with_mi_pi)
                {
                    min_time_ratio_with_mi_pi = (b.last_run().count()) / (mi);
                    min_pi = pi;
                    min_mi = mi;
                }
                break;
            }
            break;
        }
        break;
    }
    std::cout << "min_time_ratio_with_mi_pi: " << min_time_ratio_with_mi_pi << std::endl;
    std::cout << "min_pi: " << min_pi << std::endl;
    std::cout << "min_mi: " << min_mi << std::endl;
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