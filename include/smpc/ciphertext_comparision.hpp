#ifndef COFHE_CIPHERTEXT_COMPARISON_HPP_INCLUDED
#define COFHE_CIPHERTEXT_COMPARISON_HPP_INCLUDED

#include "smpc/ciphertext_multiplications.hpp"
#include "smpc/smpc_client.hpp"

namespace CoFHE {
template <typename CryptoSystem, typename PKCEncryptor,typename SHECryptoSystem>
class SMPCCipherTextComparator {
  public:
    using CipherText = typename CryptoSystem::CipherText;
    using PublicKey = typename CryptoSystem::PublicKey;
    SMPCCipherTextComparator(
        SMPCClient<CryptoSystem, PKCEncryptor,SHECryptoSystem>& smpc_client)
        : cryptosystem_m(smpc_client.crypto_system()),
          public_key_m(smpc_client.network_public_key()),
          smpc_client_m(smpc_client), ciphertext_multiplier_m(smpc_client) {}

    CipherText gteq(const CipherText& ct1, const CipherText& ct2) {
        // r1,r2 = smpc_client_m.get_comparison_pair(1);
        // result = r1*(ct1 - ct2) + r2;
        auto random_pair = smpc_client_m.get_comparision_pairs(1);
        auto res = cryptosystem_m.add_ciphertexts(
            public_key_m,
            ciphertext_multiplier_m.multiply_ciphertexts(
                *random_pair.at(0, 0),
                cryptosystem_m.add_ciphertexts(
                    public_key_m, ct1,
                    cryptosystem_m.negate_ciphertext(public_key_m, ct2))),
            *random_pair.at(0, 1));
        free_random_pair(random_pair);
        return res;
    }

    Tensor<CipherText*> gteq_tensor(const Tensor<CipherText*>& ct1,
                                    const Tensor<CipherText*>& ct2) {
        // number of elements must be same
        // we do not check it in this func
        auto ct1_flattended = ct1;
        ct1_flattended.flatten();
        auto ct2_flattended = ct2;
        ct2_flattended.flatten();

        auto random_pair =
            smpc_client_m.get_comparision_pairs(ct1_flattended.size());
        Tensor<CipherText*> rt1(ct1_flattended.size(), nullptr),
            rt2(ct1_flattended.size(), nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < ct1_flattended.size();
                                                i++) {
            rt1.at(i) = random_pair.at(i, 0);
            rt2.at(i) = random_pair.at(i, 1);
        }
        auto res = cryptosystem_m.add_ciphertext_tensors(
            public_key_m,
            ciphertext_multiplier_m.multiply_ciphertext_tensors(
                rt1, cryptosystem_m.add_ciphertext_tensors(
                         public_key_m, ct1_flattended,
                         cryptosystem_m.negate_ciphertext_tensor(
                             public_key_m, ct2_flattended))),
            rt2);
        free_random_pair(random_pair);
        res.reshape(ct1.shape());
        return res;
    }

    CipherText lteq(const CipherText& ct1, const CipherText& ct2) {
        return gteq(ct2, ct1);
    }

    Tensor<CipherText*> lteq_tensor(const Tensor<CipherText*>& ct1,
                                    const Tensor<CipherText*>& ct2) {
        return gteq_tensor(ct2, ct1);
    }

    CipherText eq(const CipherText& ct1, const CipherText& ct2) {
        return ciphertext_multiplier_m.multiply_ciphertexts(lteq(ct1, ct2),
                                                            gteq(ct1, ct2));
    }

    Tensor<CipherText*> eq_tensor(const Tensor<CipherText*>& ct1,
                                  const Tensor<CipherText*>& ct2) {
        auto lteq_res = lteq_tensor(ct1, ct2);
        auto gteq_res = gteq_tensor(ct1, ct2);
        lteq_res.flatten();
        gteq_res.flatten();
        auto res = ciphertext_multiplier_m.multiply_ciphertext_tensors(
            lteq_res, gteq_res);
        res.reshape(ct1.shape());
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < gteq_res.size(); i++) {
            delete lteq_res.at(i);
            delete gteq_res.at(i);
        }
        return res;
    }

    CipherText neq(const CipherText& ct1, const CipherText& ct2) {
        return cryptosystem_m.negate_ciphertext(public_key_m, eq(ct1, ct2));
    }

    Tensor<CipherText*> neq_tensor(const Tensor<CipherText*>& ct1,
                                   const Tensor<CipherText*>& ct2) {
        return cryptosystem_m.negate_ciphertext_tensor(public_key_m,
                                                       eq_tensor(ct1, ct2));
    }

    CipherText gt(const CipherText& ct1, const CipherText& ct2) {
        return ciphertext_multiplier_m.multiply_ciphertexts(
            gteq(ct1, ct2),
            cryptosystem_m.negate_ciphertext(public_key_m, eq(ct1, ct2)));
    }

    Tensor<CipherText*> gt_tensor(const Tensor<CipherText*>& ct1,
                                  const Tensor<CipherText*>& ct2) {
        auto gteq_res = gteq_tensor(ct1, ct2);
        auto neq_res = neq_tensor(ct1, ct2);
        gteq_res.flatten();
        neq_res.flatten();
        auto res = ciphertext_multiplier_m.multiply_ciphertext_tensors(gteq_res,
                                                                       neq_res);
        res.reshape(ct1.shape());
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < gteq_res.size(); i++) {
            delete gteq_res.at(i);
            delete neq_res.at(i);
        }
        return res;
    }

    CipherText lt(const CipherText& ct1, const CipherText& ct2) {
        return gt(ct2, ct1);
    }

    Tensor<CipherText*> lt_tensor(const Tensor<CipherText*>& ct1,
                                  const Tensor<CipherText*>& ct2) {
        return gt_tensor(ct2, ct1);
    }

  private:
    CryptoSystem cryptosystem_m;
    PublicKey public_key_m;
    SMPCClient<CryptoSystem, PKCEncryptor,SHECryptoSystem>& smpc_client_m;
    SMPCCipherTextMultiplier<CryptoSystem, PKCEncryptor,SHECryptoSystem>
        ciphertext_multiplier_m;

    void free_random_pair(Tensor<CipherText*>& random_pair) {
        random_pair.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < random_pair.size(); i++) {
            delete random_pair.at(i);
        }
    }
};
} // namespace CoFHE

#endif // COFHE_CIPHERTEXT_COMPARISON_HPP_INCLUDED