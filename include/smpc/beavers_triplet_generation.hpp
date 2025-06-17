#ifndef COFHE_BEAVERS_TRIPLET_GENERATION_HPP_INCLUDED
#define COFHE_BEAVERS_TRIPLET_GENERATION_HPP_INCLUDED

#include <gmp.h>

#include "common/tensor.hpp"

namespace CoFHE {

template <typename CryptoSystem, typename SHECryptoSystem>
class BeaversTripletGenerator {
  public:
    using PublicKey = typename CryptoSystem::PublicKey;
    using CipherText = typename CryptoSystem::CipherText;
    using PlainText = typename CryptoSystem::PlainText;
    using PartialDecryptionResult =
        typename CryptoSystem::PartialDecryptionResult;
    using SHECipherText = typename SHECryptoSystem::CipherText;
    using SHEPlainText = typename SHECryptoSystem::PlainText;
    using SHEPartialDecryptionResult =
        typename SHECryptoSystem::PartialDecryptionResult;

    BeaversTripletGenerator(const CryptoSystem& cs,
                            const typename CryptoSystem::PublicKey& pk,
                            const BeaversTripletGenerationDetails& details)
        : cs_m(cs), pk_m(pk),
          she_cs_m(details.security_level(), details.plaintext_modulus(),
                   details.multiplicative_depth(), details.crypto_context()),
          she_pk_m(she_cs_m.deserialize_public_key(
              details.serialized_she_public_key())),
          ab_pair_lower_bound_she_m(
              she_cs_m.make_plaintext(details.ab_pair_lower_bound())),
          ab_pair_upper_bound_she_m(
              she_cs_m.make_plaintext(details.ab_pair_upper_bound())) {
        init(details);
    }

    std::string generate_randomness(size_t size) {
        Tensor<PlainText*> triplets(size, 3);
        Tensor<SHEPlainText*> she_triplets(size, 3);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            auto sn1 = generate_random_num();
            auto sn2 = generate_random_num();
            auto sn3 = generate_random_num();
            triplets.at(i, 0) = new PlainText(cs_m.make_plaintext(sn1));
            triplets.at(i, 1) = new PlainText(cs_m.make_plaintext(sn2));
            triplets.at(i, 2) = new PlainText(cs_m.make_plaintext(sn3));
            she_triplets.at(i, 0) =
                new SHEPlainText(she_cs_m.make_plaintext(sn1));
            she_triplets.at(i, 1) =
                new SHEPlainText(she_cs_m.make_plaintext(sn2));
            she_triplets.at(i, 2) =
                new SHEPlainText(she_cs_m.make_plaintext(sn3));
        }
        auto cts = cs_m.encrypt_tensor(pk_m, triplets);
        auto she_cts = she_cs_m.encrypt_tensor(she_pk_m, she_triplets);
        auto serialized_cts = cs_m.serialize_ciphertext_tensor(cts);
        auto serialized_she_cts = she_cs_m.serialize_ciphertext_tensor(she_cts);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            delete triplets.at(i, 0);
            delete triplets.at(i, 1);
            delete triplets.at(i, 2);
            delete she_triplets.at(i, 0);
            delete she_triplets.at(i, 1);
            delete she_triplets.at(i, 2);
            delete cts.at(i, 0);
            delete cts.at(i, 1);
            delete cts.at(i, 2);
            delete she_cts.at(i, 0);
            delete she_cts.at(i, 1);
            delete she_cts.at(i, 2);
        }
        return std::to_string(serialized_cts.size()) + "\n" +
               std::to_string(serialized_she_cts.size()) + "\n" +
               serialized_cts + serialized_she_cts;
    }

    std::pair<Tensor<CipherText*>, Tensor<SHECipherText*>>
    accumulate_randomness(const std::vector<std::string>& data) {
        std::vector<Tensor<CipherText*>> tensors;
        std::vector<Tensor<SHECipherText*>> she_tensors;
        for (const auto& d : data) {
            size_t pos = d.find('\n');
            size_t cs_size = std::stoul(d.substr(0, pos));
            size_t pos2 = d.find('\n', pos + 1);
            size_t she_size = std::stoul(d.substr(pos + 1, pos2 - pos - 1));
            tensors.push_back(cs_m.deserialize_ciphertext_tensor(
                d.substr(pos2 + 1, cs_size)));
            she_tensors.push_back(she_cs_m.deserialize_ciphertext_tensor(
                d.substr(pos2 + 1 + cs_size, she_size)));
            if (she_tensors.back().shape() != tensors.back().shape()) {
                throw std::runtime_error(
                    "Shape mismatch between SHE and CS tensors");
            }
        }
        // can be done in parallel reduction
        auto acc_tensor =
            cs_m.add_ciphertext_tensors(pk_m, tensors[0], tensors[1]);
        auto acc_she_tensor = she_cs_m.add_ciphertext_tensors(
            she_pk_m, she_tensors[0], she_tensors[1]);
        for (size_t i = 2; i < tensors.size(); i++) {
            auto new_acc_tensor =
                cs_m.add_ciphertext_tensors(pk_m, acc_tensor, tensors[i]);
            auto new_acc_she_tensor = she_cs_m.add_ciphertext_tensors(
                she_pk_m, acc_she_tensor, she_tensors[i]);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                    j < acc_tensor.size();
                                                    j++) {
                delete acc_tensor.at(j, 0);
                delete acc_tensor.at(j, 1);
                delete acc_tensor.at(j, 2);
                delete acc_she_tensor.at(j, 0);
                delete acc_she_tensor.at(j, 1);
                delete acc_she_tensor.at(j, 2);
            }
            acc_tensor = new_acc_tensor;
            acc_she_tensor = new_acc_she_tensor;
        }
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0;
                                                           i < tensors.size();
                                                           i++) {
            for (size_t j = 0; j < tensors[0].size(); j++) {
                delete tensors[i].at(j, 0);
                delete tensors[i].at(j, 1);
                delete tensors[i].at(j, 2);
                delete she_tensors[i].at(j, 0);
                delete she_tensors[i].at(j, 1);
                delete she_tensors[i].at(j, 2);
            }
        }
        return {acc_tensor, acc_she_tensor};
    }

    std::string generate_ab_pairs(size_t size) {
        Tensor<SHEPlainText*> ab_pairs(size, 2);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            auto a = she_cs_m.generate_random_plaintext(
                ab_pair_lower_bound_she_m, ab_pair_upper_bound_she_m);
            auto b = she_cs_m.generate_random_plaintext(
                ab_pair_lower_bound_she_m, ab_pair_upper_bound_she_m);
            ab_pairs.at(i, 0) = new SHEPlainText(a);
            ab_pairs.at(i, 1) = new SHEPlainText(b);
        }
        auto she_cts = she_cs_m.encrypt_tensor(she_pk_m, ab_pairs);
        auto serialized_she_cts = she_cs_m.serialize_ciphertext_tensor(she_cts);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            delete ab_pairs.at(i, 0);
            delete ab_pairs.at(i, 1);
            delete she_cts.at(i, 0);
            delete she_cts.at(i, 1);
        }
        return serialized_she_cts;
    }

    std::pair<std::string, Tensor<SHECipherText*>> prepare_pairs_for_conversion(
        const std::vector<std::string>& data,
        const Tensor<SHECipherText*> acc_randomness_tensor) {
        std::vector<Tensor<SHECipherText*>> tensors;
        for (const auto& d : data)
            tensors.push_back(she_cs_m.deserialize_ciphertext_tensor(d));
        // can be done in parallel reduction
        auto acc_tensor =
            she_cs_m.add_ciphertext_tensors(she_pk_m, tensors[0], tensors[1]);
        for (size_t i = 2; i < tensors.size(); i++) {
            auto new_acc_tensor = she_cs_m.add_ciphertext_tensors(
                she_pk_m, acc_tensor, tensors[i]);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                    j < acc_tensor.size();
                                                    j++) {
                delete acc_tensor.at(j, 0);
                delete acc_tensor.at(j, 1);
            }
            acc_tensor = new_acc_tensor;
        }
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0;
                                                           i < tensors.size();
                                                           i++) {
            for (size_t j = 0; j < tensors[0].size(); j++) {
                delete tensors[i].at(j, 0);
                delete tensors[i].at(j, 1);
            }
        }

        if (acc_randomness_tensor.size() != acc_tensor.size()) {
            throw std::runtime_error(
                "Shape mismatch between accumulated randomness and SHE tensor");
        }
        Tensor<SHECipherText*> triplets(acc_tensor.size(), 3, nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < acc_tensor.size(); i++) {
            triplets.at(i, 0) = new SHECipherText(she_cs_m.add_ciphertexts(
                she_pk_m, *acc_tensor.at(i, 0),
                she_cs_m.negate_ciphertext(she_pk_m,
                                           *acc_randomness_tensor.at(i, 0))));
            triplets.at(i, 1) = new SHECipherText(she_cs_m.add_ciphertexts(
                she_pk_m, *acc_tensor.at(i, 1),
                she_cs_m.negate_ciphertext(she_pk_m,
                                           *acc_randomness_tensor.at(i, 1))));
            triplets.at(i, 2) = new SHECipherText(she_cs_m.add_ciphertexts(
                she_pk_m,
                she_cs_m.multiply_ciphertexts(she_pk_m, *acc_tensor.at(i, 0),
                                              *acc_tensor.at(i, 1)),
                she_cs_m.negate_ciphertext(she_pk_m,
                                           *acc_randomness_tensor.at(i, 2))));
        }
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < acc_tensor.size(); i++) {
            delete acc_tensor.at(i, 0);
            delete acc_tensor.at(i, 1);
        }
        return {she_cs_m.serialize_ciphertext_tensor(triplets), triplets};
    }

    std::string
    partial_decrypt_she_triplets(const std::string& serialized_triplets,
                                 bool lead) {
        auto she_triplets =
            she_cs_m.deserialize_ciphertext_tensor(serialized_triplets);
        if (she_sk_m == nullptr) {
            throw std::runtime_error(
                "Partial decryption requires a valid SHE secret key");
        }
        auto she_pdrs =
            she_cs_m.partial_decrypt_tensor(*she_sk_m, she_triplets, lead);
        auto serialized_pdrs =
            she_cs_m.serialize_partial_decryption_result_tensor(she_pdrs);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < she_triplets.size(); i++) {
            delete she_triplets.at(i, 0);
            delete she_triplets.at(i, 1);
            delete she_triplets.at(i, 2);
            delete she_pdrs.at(i, 0);
            delete she_pdrs.at(i, 1);
            delete she_pdrs.at(i, 2);
        }
        return serialized_pdrs;
    }

    Tensor<CipherText*> finalize_beavers_triplets(
        const std::vector<std::string>& partial_decryptions,
        const Tensor<SHECipherText*>& triplets,
        const Tensor<CipherText*>& acc_randomness_tensor) {
        std::vector<Tensor<SHEPartialDecryptionResult*>> she_pdrs;
        for (const auto& d : partial_decryptions) {
            she_pdrs.push_back(
                she_cs_m.deserialize_partial_decryption_result_tensor(d));
        }
        auto she_pt_triplets =
            she_cs_m.combine_partial_decryption_results_tensor(triplets,
                                                               she_pdrs);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0;
                                                           i < she_pdrs.size();
                                                           i++) {
            for (size_t j = 0; j < she_pdrs[0].size(); j++) {
                delete she_pdrs[i].at(j, 0);
                delete she_pdrs[i].at(j, 1);
                delete she_pdrs[i].at(j, 2);
            }
        }
        Tensor<PlainText*> pt_triplets(she_pt_triplets.size(), 3, nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < she_pt_triplets.size();
                                                i++) {
            pt_triplets.at(i, 0) = new PlainText(cs_m.make_plaintext(
                she_cs_m.get_plaintext_string(*she_pt_triplets.at(i, 0))));
            pt_triplets.at(i, 1) = new PlainText(cs_m.make_plaintext(
                she_cs_m.get_plaintext_string(*she_pt_triplets.at(i, 1))));
            pt_triplets.at(i, 2) = new PlainText(cs_m.make_plaintext(
                she_cs_m.get_plaintext_string(*she_pt_triplets.at(i, 2))));
        }
        auto ct_triplets = cs_m.encrypt_tensor(pk_m, pt_triplets);
        auto final_triplets = cs_m.add_ciphertext_tensors(
            pk_m, ct_triplets, acc_randomness_tensor);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < she_pt_triplets.size();
                                                i++) {
            delete she_pt_triplets.at(i, 0);
            delete she_pt_triplets.at(i, 1);
            delete she_pt_triplets.at(i, 2);
            delete pt_triplets.at(i, 0);
            delete pt_triplets.at(i, 1);
            delete pt_triplets.at(i, 2);
            delete ct_triplets.at(i, 0);
            delete ct_triplets.at(i, 1);
            delete ct_triplets.at(i, 2);
        }
        return final_triplets;
    }

  private:
    CryptoSystem cs_m;
    CryptoSystem::PublicKey pk_m;
    SHECryptoSystem she_cs_m;
    SHECryptoSystem::PublicKey she_pk_m;
    SHEPlainText ab_pair_lower_bound_she_m;
    SHEPlainText ab_pair_upper_bound_she_m;
    gmp_randstate_t random_state_m;
    mpz_t randomness_lower_bound_m;
    mpz_t randomness_upper_bound_m;
    SHECryptoSystem::SecretKeyShare* she_sk_m = nullptr;

    void init(const BeaversTripletGenerationDetails& details) {
        gmp_randinit_default(random_state_m);
        gmp_randseed_ui(
            random_state_m,
            std::chrono::system_clock::now().time_since_epoch().count());
        mpz_init_set_str(randomness_lower_bound_m,
                         details.randomness_lower_bound().c_str(), 10);
        mpz_init_set_str(randomness_upper_bound_m,
                         details.randomness_upper_bound().c_str(), 10);
        mpz_sub(randomness_upper_bound_m, randomness_upper_bound_m,
                randomness_lower_bound_m);

        if (!details.serialized_she_sk_share().empty()) {
            she_sk_m = new SHECryptoSystem::SecretKeyShare(
                she_cs_m.deserialize_secret_key_share(
                    details.serialized_she_sk_share()));
        }
    }

    std::string generate_random_num() {
        mpz_t random_num;
        mpz_init(random_num);
        mpz_urandomm(random_num, random_state_m, randomness_upper_bound_m);
        mpz_add(random_num, random_num, randomness_lower_bound_m);
        std::string random_num_str = mpz_get_str(NULL, 10, random_num);
        mpz_clear(random_num);
        return random_num_str;
    }
};
} // namespace CoFHE
#endif