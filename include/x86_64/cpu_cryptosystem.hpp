#ifndef CPU_CRYPTO_SYSTEM_HPP_INCLUDED
#define CPU_CRYPTO_SYSTEM_HPP_INCLUDED

#include <sstream>
#include <chrono>
#include <iostream>
#include <vector>
#include <memory>
#include "bicycl.hpp"
// we need mpn_scan1
#include "gmp.h"

#include "./common/algorithms.hpp"
#include "./common/macros.hpp"
#include "./common/vector.hpp"
#include "./common/tensor.hpp"
#include "./common/pointers.hpp"
#include "./openmp.hpp"

namespace CoFHE
{

    class CPUCryptoSystem
    {
    public:
        using SecretKey = BICYCL::CL_HSM2k::SecretKey;
        using SecretKeyShare = BICYCL::Mpz;
        using PublicKey = BICYCL::CL_HSM2k::PublicKey;
        using PlainText = BICYCL::Mpz;
        using CipherText = BICYCL::CL_HSM2k::CipherText;
        using PartDecryptionResult = BICYCL::QFI;

        CPUCryptoSystem(uint32_t security_level, uint32_t k, bool compact = false) : rand_gen(), hsm2k(BICYCL::CL_HSM2k(security_level, k, rand_gen, compact)), sec_level(security_level), k(k)
        {
            init();
        }
        CPUCryptoSystem(const CPUCryptoSystem &other) : rand_gen(), hsm2k(other.hsm2k), sec_level(other.sec_level), k(other.k)
        {
            init();
        }
        CPUCryptoSystem(CPUCryptoSystem &&other) : rand_gen(), hsm2k(std::move(other.hsm2k)), sec_level(other.sec_level), k(other.k)
        {
            init();
        }
        CPUCryptoSystem &operator=(const CPUCryptoSystem &other)
        {
            if (this != &other)
            {
                rand_gen = BICYCL::RandGen();
                hsm2k = other.hsm2k;
                sec_level = other.sec_level;
                k = other.k;
                init();
            }
            return *this;
        }
        CPUCryptoSystem &operator=(CPUCryptoSystem &&other)
        {
            if (this != &other)
            {
                rand_gen = BICYCL::RandGen();
                hsm2k = std::move(other.hsm2k);
                sec_level = other.sec_level;
                k = other.k;
                init();
            }
            return *this;
        }
        ~CPUCryptoSystem()
        {
            mpf_clear(scaling_factor);
            mpf_clear(mM);
            mpf_clear(mM_half);
        }
        SecretKey keygen() const;
        PublicKey keygen(const SecretKey &sk) const;
        Vector<Vector<SecretKeyShare>> keygen(const SecretKey &sk, size_t threshold, size_t num_parties) const;
        CipherText encrypt(const PublicKey &pk, const PlainText &pt) const;
        Vector<CipherText *> encrypt_vector(const PublicKey &pk, const Vector<PlainText *> &pt) const;
        Tensor<CipherText *> encrypt_tensor(const PublicKey &pk, const Tensor<PlainText *> &pt) const;
        PlainText decrypt(const SecretKey &sk, const CipherText &ct) const;
        Vector<PlainText *> decrypt_vector(const SecretKey &sk, const Vector<CipherText *> &ct) const;
        Tensor<PlainText *> decrypt_tensor(const SecretKey &sk, const Tensor<CipherText *> &ct) const;
        PartDecryptionResult part_decrypt(const SecretKeyShare &sks, const CipherText &ct) const;
        Vector<PartDecryptionResult *> part_decrypt_vector(const SecretKeyShare &sks, const Vector<CipherText *> &ct) const;
        Tensor<PartDecryptionResult *> part_decrypt_tensor(const SecretKeyShare &sks, const Tensor<CipherText *> &ct) const;
        PlainText combine_part_decryption_results(const CipherText &ct,
                                                  const Vector<PartDecryptionResult> &pdrs) const;
        Vector<PlainText *> combine_part_decryption_results_vector(const CipherText &ct,
                                                                   const Vector<PartDecryptionResult *> &pdrs) const;
        Tensor<PlainText *> combine_part_decryption_results_tensor(const Tensor<CipherText *> &ct,
                                                                   const Vector<Tensor<PartDecryptionResult *>> &pdrs) const;
        CipherText add_ciphertexts(const PublicKey &pk, const CipherText &ct1, const CipherText &ct2) const;
        CipherText scal_ciphertext(const PublicKey &pk, const PlainText &s, const CipherText &ct) const;

        Vector<CipherText *> add_ciphertext_vectors(const PublicKey &pk, const Vector<CipherText *> &ct1, const Vector<CipherText *> &ct2) const;
        Vector<CipherText *> scal_ciphertext_vector(const PublicKey &pk, const PlainText &s, const Vector<CipherText *> &ct) const;
        Vector<CipherText *> scal_ciphertext_vector(const PublicKey &pk, const Vector<PlainText *> &s, const Vector<CipherText *> &ct) const;

        Tensor<CipherText *> add_ciphertext_tensors(const PublicKey &pk, const Tensor<CipherText *> &ct1, const Tensor<CipherText *> &ct2) const;
        Tensor<CipherText *> scal_ciphertext_tensors(const PublicKey &pk, const Tensor<PlainText *> &s, const Tensor<CipherText *> &ct) const;

        PlainText generate_random_plaintext() const;
        Vector<PlainText> generate_random_beavers_triplet() const;
        PlainText add_plaintexts(const PlainText &pt1, const PlainText &pt2) const;
        PlainText multiply_plaintexts(const PlainText &pt1, const PlainText &pt2) const;
        Tensor<PlainText *> add_plaintext_tensors(const Tensor<PlainText *> &pt1, const Tensor<PlainText *> &pt2) const;
        Tensor<PlainText *> multiply_plaintext_tensors(const Tensor<PlainText *> &pt1, const Tensor<PlainText *> &pt2) const;
        PlainText negate_plaintext(const PlainText &s) const;
        Tensor<PlainText *> negate_plaintext_tensor(const Tensor<PlainText *> &pt) const;
        CipherText negate_ciphertext(const PublicKey &pk, const CipherText &ct) const;
        Tensor<CipherText *> negate_ciphertext_tensor(const PublicKey &pk, const Tensor<CipherText *> &ct) const;

        PlainText make_plaintext(float value) const;
        float get_float_from_plaintext(const PlainText &pt) const;

        String serialize() const;
        String serialize_secret_key(const SecretKey &sk) const;
        String serialize_secret_key_share(const SecretKeyShare &sks) const;
        String serialize_public_key(const PublicKey &pk) const;
        String serialize_plaintext(const PlainText &pt) const;
        String serialize_ciphertext(const CipherText &ct) const;
        String serialize_part_decryption_result(const PartDecryptionResult &pdr) const;
        String serialize_plaintext_tensor(const Tensor<PlainText *> &pt_cpu) const;
        String serialize_ciphertext_tensor(const Tensor<CipherText *> &ct_cpu) const;
        String serialize_part_decryption_result_tensor(const Tensor<PartDecryptionResult *> &pdr_cpu) const;
        static CPUCryptoSystem deserialize(const String &data);
        SecretKey deserialize_secret_key(const String &data) const;
        SecretKeyShare deserialize_secret_key_share(const String &data) const;
        PublicKey deserialize_public_key(const String &data) const;
        PlainText deserialize_plaintext(const String &data) const;
        CipherText deserialize_ciphertext(const String &data) const;
        PartDecryptionResult deserialize_part_decryption_result(const String &data) const;
        Tensor<PlainText *> deserialize_plaintext_tensor(const String &data) const;
        Tensor<CipherText *> deserialize_ciphertext_tensor(const String &data) const;
        Tensor<PartDecryptionResult *> deserialize_part_decryption_result_tensor(const String &data) const;

        BICYCL::RandGen &get_rand_gen() { return rand_gen; }
        const BICYCL::CL_HSM2k &get_hsm2k() const { return hsm2k; }

    private:
        mutable BICYCL::RandGen rand_gen;
        BICYCL::CL_HSM2k hsm2k;
        uint32_t sec_level;
        uint32_t k;
        mpf_t scaling_factor;
        mpf_t mM;
        mpf_t mM_half;

        void init()
        {
            mpf_init(this->scaling_factor);
            mpf_init(this->mM);
            mpf_init(this->mM_half);
            mpf_set_d(this->scaling_factor, 2);
            mpf_set_d(this->mM, 2);
            // change this to on the basis of accuracy
            mpf_pow_ui(this->scaling_factor, this->scaling_factor, 0); // 8
            mpf_pow_ui(this->mM, this->mM, k);
            mpf_div_ui(this->mM_half, this->mM, 2);
        }

        BICYCL::CL_HSM2k::ClearText to_plaintext(const PlainText &pt) const
        {
            return BICYCL::CL_HSM2k::ClearText(hsm2k, pt);
        }

        BICYCL::Mpz to_mpz(const BICYCL::CL_HSM2k::ClearText &ct) const
        {
            return ct;
        }
    };
#include "qfi.inl"
#include "cpu_cryptosystem.inl"
#include "cpu_cryptosystem_distributed.inl"
#include "cpu_cryptosystem_vector_ops.inl"
#include "cpu_cryptosystem_tensor_ops.inl"
}

#endif