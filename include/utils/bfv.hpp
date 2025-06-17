#ifndef CoFHE_BFV_HPP_INCLUDED
#define CoFHE_BFV_HPP_INCLUDED

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/algorithms.hpp"
#include "common/macros.hpp"
#include "common/openmp.hpp"
#include "common/pointers.hpp"
#include "common/tensor.hpp"
#include <openfhe/core/lattice/hal/lat-backend.h>
#include <openfhe/core/utils/inttypes.h>
#include <openfhe/pke/ciphertext-ser.h>
#include <openfhe/pke/cryptocontext-ser.h>
#include <openfhe/pke/encoding/plaintext-fwd.h>
#include <openfhe/pke/key/evalkey-fwd.h>
#include <openfhe/pke/key/key-ser.h>
#include <openfhe/pke/key/privatekey-fwd.h>
#include <openfhe/pke/key/publickey-fwd.h>
#include <openfhe/pke/openfhe.h>
#include <openfhe/pke/scheme/bfvrns/bfvrns-ser.h>

namespace CoFHE {
class BFVCryptoSystem {
  public:
    using CipherText = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
    using PlainText = lbcrypto::Plaintext;
    using PublicKey = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
    using SecretKey = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
    // using SecretKeyShare = std::unordered_map<usint, lbcrypto::DCRTPoly>;
    using SecretKeyShare = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
    using PartialDecryptionResult = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;

    BFVCryptoSystem(size_t security_level, const std::string& plaintext_modulus,
                    const std::string& multiplicative_depth,
                    const std::string& crypto_context)
        : security_level_m(security_level),
          plaintext_modulus_m(plaintext_modulus),
          multiplicative_depth_m(multiplicative_depth) {
        init(crypto_context);
    }

    std::pair<PublicKey, std::vector<SecretKeyShare>> keygen(size_t threshold,
                                                             size_t n_parties) {
        std::vector<lbcrypto::KeyPair<lbcrypto::DCRTPoly>> keyPairs(n_parties);
        keyPairs[0] = cc_m->KeyGen();
        for (size_t i = 1; i < n_parties; ++i) {
            keyPairs[i] = cc_m->MultipartyKeyGen(keyPairs[i - 1].publicKey);
        }
        auto jointPublicKey = keyPairs[n_parties - 1].publicKey;

        std::string share_type = "shamir";
        std::vector<std::unordered_map<usint, lbcrypto::DCRTPoly>>
            secretKeyShares(n_parties);
        for (size_t i = 0; i < n_parties; ++i) {
            secretKeyShares[i] = cc_m->ShareKeys(
                keyPairs[i].secretKey, n_parties, threshold, i + 1, share_type);
        }
        auto jointRelinKey =
            cc_m->KeySwitchGen(keyPairs[0].secretKey, keyPairs[0].secretKey);
        for (size_t i = 1; i < n_parties; ++i) {
            auto relinKey_i = cc_m->MultiKeySwitchGen(
                keyPairs[i].secretKey, keyPairs[i].secretKey, jointRelinKey);
            jointRelinKey = cc_m->MultiAddEvalKeys(
                jointRelinKey, relinKey_i, keyPairs[i].publicKey->GetKeyTag());
        }

        auto jointPublicKeyTag = jointPublicKey->GetKeyTag();
        auto evalMultFinal = cc_m->MultiMultEvalKey(
            keyPairs[0].secretKey, jointRelinKey, jointPublicKeyTag);
        for (size_t i = 1; i < n_parties; ++i) {
            auto evalMult_i = cc_m->MultiMultEvalKey(
                keyPairs[i].secretKey, jointRelinKey, jointPublicKeyTag);
            evalMultFinal = cc_m->MultiAddEvalMultKeys(
                evalMultFinal, evalMult_i, evalMult_i->GetKeyTag());
        }
        cc_m->InsertEvalMultKey({evalMultFinal});

        cc_m->EvalSumKeyGen(keyPairs[0].secretKey);
        auto evalSumKeysAggregated = std::make_shared<
            std::map<usint, lbcrypto::EvalKey<lbcrypto::DCRTPoly>>>(
            cc_m->GetEvalSumKeyMap(keyPairs[0].secretKey->GetKeyTag()));
        for (size_t i = 1; i < n_parties; ++i) {
            auto evalSumKeys_i = cc_m->MultiEvalSumKeyGen(
                keyPairs[i].secretKey, evalSumKeysAggregated,
                keyPairs[i].publicKey->GetKeyTag());
            evalSumKeysAggregated =
                cc_m->MultiAddEvalSumKeys(evalSumKeysAggregated, evalSumKeys_i,
                                          keyPairs[i].publicKey->GetKeyTag());
        }
        cc_m->InsertEvalSumKey(evalSumKeysAggregated);
        std::vector<SecretKeyShare> keyPairsS(n_parties);
        for (size_t i = 0; i < n_parties; ++i)
            keyPairsS[i] = keyPairs[i].secretKey;
        return {jointPublicKey, keyPairsS};
    }

    PlainText make_plaintext(const std::string& value) {
        return cc_m->MakePackedPlaintext(
            {static_cast<long int>(std::stoull(value))});
    }

    CipherText encrypt(const PublicKey& public_key,
                       const PlainText& plaintext) {
        return cc_m->Encrypt(public_key, plaintext);
    }

    CipherText add_ciphertexts(const PublicKey& public_key,
                               const CipherText& ct1, const CipherText& ct2) {
        return cc_m->EvalAdd(ct1, ct2);
    }
    CipherText multiply_ciphertexts(const PublicKey& public_key,
                                    const CipherText& ct1,
                                    const CipherText& ct2) {
        return cc_m->EvalMult(ct1, ct2);
    }
    CipherText negate_ciphertext(const PublicKey& public_key,
                                 const CipherText& ct) {
        return cc_m->EvalNegate(ct);
    }
    CipherText scal_ciphertext(const PublicKey& public_key,
                               const PlainText& scalar, const CipherText& ct) {
        return cc_m->EvalMult(ct, scalar);
    }
    Tensor<CipherText*> encrypt_tensor(const PublicKey& public_key,
                                       const Tensor<PlainText*>& plaintexts) {
        Tensor<CipherText*> cts(plaintexts.shape(), nullptr);
        auto pts_flattened = plaintexts;
        pts_flattened.flatten();
        cts.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i <
                                                pts_flattened.num_elements();
                                                i++) {
            cts[i] =
                new CipherText(cc_m->Encrypt(public_key, *pts_flattened[i]));
        }
        cts.reshape(plaintexts.shape());
        return cts;
    }
    Tensor<CipherText*> add_ciphertext_tensors(const PublicKey& public_key,
                                               const Tensor<CipherText*>& ct1,
                                               const Tensor<CipherText*>& ct2) {
        if (ct1.shape() != ct2.shape()) {
            throw std::invalid_argument("Tensor shapes must be equal");
        }
        Tensor<CipherText*> res(ct1.shape(), nullptr);
        auto ct1_flattened = ct1;
        auto ct2_flattened = ct2;
        ct1_flattened.flatten();
        ct2_flattened.flatten();
        res.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i <
                                                ct1_flattened.num_elements();
                                                i++) {
            res[i] = new CipherText(
                cc_m->EvalAdd(*ct1_flattened[i], *ct2_flattened[i]));
        }
        res.reshape(ct1.shape());
        return res;
    }

    Tensor<PartialDecryptionResult*>
    partial_decrypt_tensor(const SecretKeyShare& secret_key_share,
                           const Tensor<CipherText*>& ct, bool lead = false) {
        Tensor<PartialDecryptionResult*> pdr(ct.shape(), nullptr);
        pdr.flatten();
        auto ct_flattened = ct;
        ct_flattened.flatten();
        if (lead) {
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    ct_flattened.num_elements();
                                                    i++) {
                pdr.at(i) =
                    new PartialDecryptionResult(cc_m->MultipartyDecryptLead(
                        {*ct_flattened[i]}, secret_key_share)[0]);
            }
        } else {
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    ct_flattened.num_elements();
                                                    i++) {
                pdr.at(i) =
                    new PartialDecryptionResult(cc_m->MultipartyDecryptMain(
                        {*ct_flattened[i]}, secret_key_share)[0]);
            }
        }
        pdr.reshape(ct.shape());
        return pdr;
    }

    Tensor<PlainText*> combine_partial_decryption_results_tensor(
        const Tensor<CipherText*>& ct,
        const std::vector<Tensor<PartialDecryptionResult*>>& pdrs) {
        Tensor<PlainText*> pts(ct.shape(), nullptr);
        auto ct_flattened = ct;
        ct_flattened.flatten();
        std::vector<Tensor<PartialDecryptionResult*>> pdrs_flattened;
        for (size_t i = 0; i < pdrs.size(); i++) {
            pdrs_flattened.push_back(pdrs[i]);
            pdrs_flattened[i].flatten();
        }
        pts.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < ct_flattened.num_elements();
                                                i++) {
            std::vector<PartialDecryptionResult> pdrs_vec(pdrs.size());
            for (size_t j = 0; j < pdrs.size(); j++) {
                pdrs_vec[j] = *pdrs_flattened[j][i];
            }
            PlainText pt;
            cc_m->MultipartyDecryptFusion(pdrs_vec, &pt);
            pts.at(i) = new PlainText(pt);
        }
        pts.reshape(ct.shape());
        return pts;
    }

    std::string get_plaintext_string(const PlainText& plaintext) {
        return std::to_string(plaintext->GetPackedValue()[0]);
    }

    PlainText generate_random_plaintext(const PlainText& lower_bound,
                                        const PlainText& upper_bound) {
        return make_plaintext(
            std::to_string((std::rand() + lower_bound->GetPackedValue()[0]) %
                           upper_bound->GetPackedValue()[0]));
    }

    std::string serialize() {
        std::string cs = lbcrypto::Serial::SerializeToString(cc_m);
        std::ostringstream ss;
        cc_m->SerializeEvalMultKey(ss, lbcrypto::SerType::JSON);
        std::string eval_mult_key = ss.str();
        ss.clear();
        ss.str(std::string());
        cc_m->SerializeEvalSumKey(ss, lbcrypto::SerType::JSON);
        std::string eval_sum_key = ss.str();
        // first 16 offsets for mul key and sum key
        std::string serialized_data(
            16 + cs.size() + eval_mult_key.size() + eval_sum_key.size(), 0);
        char* data_ptr = serialized_data.data();
        uint64_t mul_key_offset = 16 + cs.size();
        memcpy(data_ptr, &mul_key_offset, 8);
        data_ptr += 8;
        uint64_t sum_key_offset = mul_key_offset + eval_mult_key.size();
        memcpy(data_ptr, &sum_key_offset, 8);
        data_ptr += 8;
        memcpy(data_ptr, cs.data(), cs.size());
        data_ptr += cs.size();
        memcpy(data_ptr, eval_mult_key.data(), eval_mult_key.size());
        data_ptr += eval_mult_key.size();
        memcpy(data_ptr, eval_sum_key.data(), eval_sum_key.size());
        return serialized_data;
    }

    std::string serialize_public_key(const PublicKey& public_key) {
        return lbcrypto::Serial::SerializeToString(public_key);
    }

    PublicKey deserialize_public_key(const std::string& serialized_pk) {
        PublicKey pk;
        lbcrypto::Serial::DeserializeFromString(pk, serialized_pk);
        return pk;
    }

    std::string
    serialize_secret_key_share(const SecretKeyShare& secret_key_share) {
        return lbcrypto::Serial::SerializeToString(secret_key_share);
    }

    SecretKeyShare
    deserialize_secret_key_share(const std::string& serialized_sk_share) {
        SecretKeyShare sk_share;
        lbcrypto::Serial::DeserializeFromString(sk_share, serialized_sk_share);
        return sk_share;
    }

    std::string serialize_ciphertext(const CipherText& ct) {
        return lbcrypto::Serial::SerializeToString(ct);
    }
    CipherText deserialize_ciphertext(const std::string& serialized_ct) {
        CipherText ct;
        lbcrypto::Serial::DeserializeFromString(ct, serialized_ct);
        return ct;
    }

    std::string serialize_ciphertext_tensor(const Tensor<CipherText*>& cts) {
        // the format is binary
        // the first 4 bytes are ndim, then next n*4 bytes are the shape, then
        // the pointer table the pointer table points to the actual ct
        // data, each entry is 8 bytes
        auto cts_flattened = cts;
        cts_flattened.flatten();
        std::vector<std::string> serialized_cts(cts_flattened.num_elements());
        // CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (size_t i = 0; i < cts_flattened.num_elements(); i++) {
            serialized_cts[i] = serialize_ciphertext(*cts_flattened[i]);
        }

        uint32_t ndim = cts.ndim();
        size_t data_size = 4 + 4 * ndim + 8 * cts.num_elements();
        std::vector<uint64_t> data_offsets(cts.num_elements(), 0);
        uint64_t last_offset = 0;
        for (size_t i = 0; i < cts_flattened.num_elements(); i++) {
            data_offsets[i] = last_offset;
            last_offset += serialized_cts[i].size();
        }
        data_size += last_offset;

        std::string data(data_size, 0);
        char* data_ptr = data.data();
        // write ndim
        memcpy(data_ptr, &ndim, 4);
        data_ptr += 4;
        // write shape
        for (size_t i = 0; i < cts.ndim(); i++) {
            uint32_t dim = cts.shape()[i];
            memcpy(data_ptr, &dim, 4);
            data_ptr += 4;
        }
        // write pointer table
        for (size_t i = 0; i < cts.num_elements(); i++) {
            memcpy(data_ptr, &data_offsets[i], 8);
            data_ptr += 8;
        }
        // write data
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i <
                                                cts_flattened.num_elements();
                                                i++) {
            memcpy(data_ptr + data_offsets[i], serialized_cts[i].data(),
                   serialized_cts[i].size());
        }
        return data;
    }

    Tensor<CipherText*>
    deserialize_ciphertext_tensor(const std::string& serialized_cts) {
        uint32_t ndim;
        const char* data_ptr = serialized_cts.data();
        memcpy(&ndim, data_ptr, 4);
        data_ptr += 4;
        std::vector<uint32_t> shape(ndim);
        uint64_t num_elements = 1;
        for (size_t i = 0; i < ndim; i++) {
            memcpy(&shape[i], data_ptr, 4);
            data_ptr += 4;
            num_elements *= shape[i];
        }

        std::vector<uint64_t> data_offsets(num_elements, 0);
        for (size_t i = 0; i < num_elements; i++) {
            memcpy(&data_offsets[i], data_ptr, 8);
            data_ptr += 8;
        }

        std::vector<size_t> shape_vec(shape.begin(), shape.end());
        Tensor<CipherText*> ciphertexts(shape_vec, nullptr);
        ciphertexts.flatten();
        uint64_t start_offset = data_ptr - serialized_cts.data();
        // CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (size_t i = 0; i < num_elements - 1; i++) {
            ciphertexts[i] = new CipherText(deserialize_ciphertext(
                serialized_cts.substr(start_offset + data_offsets[i],
                                      data_offsets[i + 1] - data_offsets[i])));
        }
        ciphertexts[num_elements - 1] =
            new CipherText(deserialize_ciphertext(serialized_cts.substr(
                start_offset + data_offsets[num_elements - 1],
                serialized_cts.size() - data_offsets[num_elements - 1])));
        ciphertexts.reshape(shape_vec);
        return ciphertexts;
    }

    std::string
    serialize_partial_decryption_result(const PartialDecryptionResult& pdr) {
        return lbcrypto::Serial::SerializeToString(pdr);
    }

    PartialDecryptionResult
    deserialize_partial_decryption_result(const std::string& serialized_pdr) {
        PartialDecryptionResult pdr;
        lbcrypto::Serial::DeserializeFromString(pdr, serialized_pdr);
        return pdr;
    }

    std::string serialize_partial_decryption_result_tensor(
        const Tensor<PartialDecryptionResult*>& pdrs) {
        // the format is binary
        // the first 4 bytes are ndim, then next n*4 bytes are the shape, then
        // the pointer table the pointer table points to the actual ct
        // data, each entry is 8 bytes
        auto pdrs_flattened = pdrs;
        pdrs_flattened.flatten();
        std::vector<std::string> serialized_pdrs(pdrs_flattened.num_elements());
        // CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (size_t i = 0; i < pdrs_flattened.num_elements(); i++) {
            serialized_pdrs[i] =
                serialize_partial_decryption_result(*pdrs_flattened[i]);
        }

        uint32_t ndim = pdrs.ndim();
        size_t data_size = 4 + 4 * ndim + 8 * pdrs.num_elements();
        std::vector<uint64_t> data_offsets(pdrs.num_elements(), 0);
        uint64_t last_offset = 0;
        for (size_t i = 0; i < pdrs_flattened.num_elements(); i++) {
            data_offsets[i] = last_offset;
            last_offset += serialized_pdrs[i].size();
        }
        data_size += last_offset;

        std::string data(data_size, 0);
        char* data_ptr = data.data();
        // write ndim
        memcpy(data_ptr, &ndim, 4);
        data_ptr += 4;
        // write shape
        for (size_t i = 0; i < pdrs.ndim(); i++) {
            uint32_t dim = pdrs.shape()[i];
            memcpy(data_ptr, &dim, 4);
            data_ptr += 4;
        }
        // write pointer table
        for (size_t i = 0; i < pdrs.num_elements(); i++) {
            memcpy(data_ptr, &data_offsets[i], 8);
            data_ptr += 8;
        }
        // write data
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i <
                                                pdrs_flattened.num_elements();
                                                i++) {
            memcpy(data_ptr + data_offsets[i], serialized_pdrs[i].data(),
                   serialized_pdrs[i].size());
        }
        return data;
    }

    Tensor<PartialDecryptionResult*>
    deserialize_partial_decryption_result_tensor(
        const std::string& serialized_pdrs) {
        uint32_t ndim;
        const char* data_ptr = serialized_pdrs.data();
        memcpy(&ndim, data_ptr, 4);
        data_ptr += 4;
        std::vector<uint32_t> shape(ndim);
        uint64_t num_elements = 1;
        for (size_t i = 0; i < ndim; i++) {
            memcpy(&shape[i], data_ptr, 4);
            data_ptr += 4;
            num_elements *= shape[i];
        }

        std::vector<uint64_t> data_offsets(num_elements, 0);
        for (size_t i = 0; i < num_elements; i++) {
            memcpy(&data_offsets[i], data_ptr, 8);
            data_ptr += 8;
        }

        std::vector<size_t> shape_vec(shape.begin(), shape.end());
        Tensor<PartialDecryptionResult*> pdrs(shape_vec, nullptr);
        pdrs.flatten();
        uint64_t start_offset = data_ptr - serialized_pdrs.data();
        // CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (size_t i = 0; i < num_elements - 1; i++) {
            pdrs[i] = new PartialDecryptionResult(
                deserialize_partial_decryption_result(serialized_pdrs.substr(
                    start_offset + data_offsets[i],
                    data_offsets[i + 1] - data_offsets[i])));
        }
        pdrs[num_elements - 1] = new PartialDecryptionResult(
            deserialize_partial_decryption_result(serialized_pdrs.substr(
                start_offset + data_offsets[num_elements - 1],
                serialized_pdrs.size() - data_offsets[num_elements - 1])));
        pdrs.reshape(shape_vec);
        return pdrs;
    }

  private:
    size_t security_level_m; // 128, 192, or 256 bits
    std::string plaintext_modulus_m;
    std::string multiplicative_depth_m;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc_m;
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> public_key_m;

    void init(std::string crypto_context) {
        if (crypto_context.empty()) {
            lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
            parameters.SetPlaintextModulus(std::stoull(plaintext_modulus_m));
            if (security_level_m == 128) {
                parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);
            } else if (security_level_m == 192) {
                parameters.SetSecurityLevel(lbcrypto::HEStd_192_classic);
            } else if (security_level_m == 256) {
                parameters.SetSecurityLevel(lbcrypto::HEStd_256_classic);
            } else {
                throw std::invalid_argument("Invalid security level");
            }
            parameters.SetSecretKeyDist(lbcrypto::UNIFORM_TERNARY);
            parameters.SetMultiplicativeDepth(
                std::stoull(multiplicative_depth_m));
            parameters.SetBatchSize(1024);
            parameters.SetDigitSize(30);
            parameters.SetScalingModSize(60);

            lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc =
                lbcrypto::GenCryptoContext(parameters);

            cc->Enable(lbcrypto::PKE);
            cc->Enable(lbcrypto::LEVELEDSHE);
            cc->Enable(lbcrypto::ADVANCEDSHE);
            cc->Enable(lbcrypto::MULTIPARTY);
            cc_m = cc;
        } else {
            uint64_t mul_key_offset, sum_key_offset;
            const char* data_ptr = crypto_context.data();
            memcpy(&mul_key_offset, data_ptr, 8);
            data_ptr += 8;
            memcpy(&sum_key_offset, data_ptr, 8);
            data_ptr += 8;
            std::string serialized_cc(
                crypto_context.substr(16, mul_key_offset - 16));
            std::string serialized_eval_mult_key(crypto_context.substr(
                mul_key_offset, sum_key_offset - mul_key_offset));
            std::string serialized_eval_sum_key(crypto_context.substr(
                sum_key_offset, crypto_context.size() - sum_key_offset));
            lbcrypto::Serial::DeserializeFromString(cc_m, serialized_cc);
            std::istringstream ss(serialized_eval_mult_key);
            if (cc_m->DeserializeEvalMultKey(ss, lbcrypto::SerType::JSON) ==
                false) {
                throw std::runtime_error("Failed to deserialize eval mult key");
            }
            ss.clear();
            ss.str(serialized_eval_sum_key);
            if (cc_m->DeserializeEvalSumKey(ss, lbcrypto::SerType::JSON) ==
                false) {
                throw std::runtime_error("Failed to deserialize eval sum key");
            }
        }
    }
};
} // namespace CoFHE

#endif // COFHE_BFV_HPP_INCLUDED