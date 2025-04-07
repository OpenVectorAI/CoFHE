#ifndef COFHE_RSA_REENCRYPTION_HPP_INCLUDED
#define COFHE_RSA_REENCRYPTION_HPP_INCLUDED

#include "common/macros.hpp"

namespace CoFHE {
template <typename PKCEncryptor, typename CryptoSystem>
class PartialDecryptionResultReencryption {
  public:
    using CipherText = typename CryptoSystem::CipherText;
    using PlainText = typename CryptoSystem::PlainText;
    using PartialDecryptionResult =
        typename CryptoSystem::PartialDecryptionResult;
    using SecretKeyShare = typename CryptoSystem::SecretKeyShare;
    using ReencryptionKeyPair = typename PKCEncryptor::KeyPair;
    using ReencrytedMessage = typename PKCEncryptor::EncryptedMessage;

    PartialDecryptionResultReencryption(const PKCEncryptor& encryptor,
                                        const CryptoSystem& cryptosystem)
        : reencryptor_m(encryptor), crypto_system_m(cryptosystem) {}

    std::string
    reencrypt(const PartialDecryptionResult& partial_decryption_result,
              std::string serialized_reencryption_public_key) const {
        auto reencryption_public_key = reencryptor_m.deserialize_public_key(
            serialized_reencryption_public_key);
        return to_string(reencryptor_m.encrypt(
            reencryption_public_key,
            crypto_system_m.serialize_partial_decryption_result(
                partial_decryption_result)));
    }

    std::string reencrypt_tensor(
        const Tensor<PartialDecryptionResult*>&
            partial_decryption_result_tensor,
        const std::string& serialized_reencryption_public_key) const {
        auto reencryption_public_key = reencryptor_m.deserialize_public_key(
            serialized_reencryption_public_key);
        auto shape = partial_decryption_result_tensor.shape();
        auto flattened_result = partial_decryption_result_tensor;
        flattened_result.flatten();
        std::vector<std::string> reencrypted_result(flattened_result.size());
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < flattened_result.size();
                                                ++i) {
            reencrypted_result[i] = to_string(reencryptor_m.encrypt(
                reencryption_public_key,
                crypto_system_m.serialize_partial_decryption_result(
                    *flattened_result.at(i))));
        }

        return to_string(reencrypted_result);
    }

    PlainText
    decrypt(const Vector<std::string>& reencryted_partial_decryption_result,
            const CipherText& ciphertext,
            const ReencryptionKeyPair& reencryption_private_key) const {
        Vector<PartialDecryptionResult> pdrs;
        for (const auto& reencryted_message :
             reencryted_partial_decryption_result) {
            pdrs.push_back(
                crypto_system_m.deserialize_partial_decryption_result(
                    reencryptor_m.decrypt(reencryption_private_key,
                                          from_string_to_reencrypted_message(
                                              reencryted_message))));
        }
        return crypto_system_m.combine_partial_decryption_results(ciphertext,
                                                                  pdrs);
    }

    Tensor<PlainText*> decrypt_tensor(
        const Vector<std::string>& reencryted_partial_decryption_result,
        const Tensor<CipherText*>& ciphertext,
        const ReencryptionKeyPair& reencryption_private_key) const {
        Vector<Tensor<PartialDecryptionResult*>> pdrs(
            reencryted_partial_decryption_result.size(),
            Tensor<PartialDecryptionResult*>(ciphertext.shape(), nullptr));
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pdrs.size();
                                                ++i) {
            auto reencryted_pdrs =
                from_string_to_reencrypted_message_for_tensor(
                    reencryted_partial_decryption_result[i]);

            Tensor<PartialDecryptionResult*> pdr(ciphertext.shape(), nullptr);
            pdr.flatten();
            for (size_t j = 0; j < pdr.size(); ++j) {
                pdr.at(j) = new PartialDecryptionResult(
                    crypto_system_m.deserialize_partial_decryption_result(
                        reencryptor_m.decrypt(
                            reencryption_private_key,
                            from_string_to_reencrypted_message(
                                reencryted_pdrs.at(j)))));
            }
            pdr.reshape(ciphertext.shape());
            pdrs[i] = pdr;
        }
        auto res = crypto_system_m.combine_partial_decryption_results_tensor(
            ciphertext, pdrs);
        for (size_t i = 0; i < pdrs.size(); ++i) {
            pdrs[i].flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                    j < pdrs[i].num_elements();
                                                    ++j) {
                delete pdrs[i].at(j);
            }
        }
        return res;
    }

    ReencryptionKeyPair generate_reencryption_key_pair() const {
        return reencryptor_m.generate_key_pair();
    }

    std::string serialize_reencryption_private_key(
        const ReencryptionKeyPair& reencryption_private_key) const {
        return reencryptor_m.serialize_private_key(reencryption_private_key);
    }

    std::string serialize_reencryption_public_key(
        const ReencryptionKeyPair& reencryption_public_key) const {
        return reencryptor_m.serialize_public_key(reencryption_public_key);
    }

    ReencryptionKeyPair deserialize_reencryption_private_key(
        const std::string& serialized_reencryption_private_key) const {
        return reencryptor_m.deserialize_private_key(
            serialized_reencryption_private_key);
    }

    ReencryptionKeyPair deserialize_reencryption_public_key(
        const std::string& serialized_reencryption_public_key) const {
        return reencryptor_m.deserialize_public_key(
            serialized_reencryption_public_key);
    }

    // will be used by compute to node to serialize the
    // multiple reencrypted messages from cofhe node
    static std::string concatenate_reencrypted_messages(
        const Vector<std::string>& reencryted_partial_decryption_result) {
        // for now can use the same function as
        // to_string
        return to_string(reencryted_partial_decryption_result);
    }

    // will be used to by client
    static Vector<std::string>
    split_reencrypted_messages(const std::string& str) {
        return from_string_to_reencrypted_message_for_tensor(str);
    }

  private:
    PKCEncryptor reencryptor_m;
    CryptoSystem crypto_system_m;

    std::string to_string(const ReencrytedMessage& reencryted_message) const {
        return reencryted_message;
    }

    static ReencrytedMessage
    from_string_to_reencrypted_message(const std::string& str) {
        return str;
    }

    static std::string to_string(
        const std::vector<std::string>& reencryted_partial_decryption_result) {
        // the first 8 bytes represent number of messages and next
        // 8*number_of_reencrypted_messages bytes represent the offsets of
        // particular reencrypted messages in the string
        size_t offset =
            8 + (reencryted_partial_decryption_result.size()) * 8;
        std::vector<uint64_t> offsets(
            reencryted_partial_decryption_result.size());
        for (size_t i = 0; i < reencryted_partial_decryption_result.size();
             ++i) {
            offsets[i] = offset;
            offset += static_cast<uint64_t>(
                reencryted_partial_decryption_result[i].size());
        }
        size_t size =
            offset ;
        std::string result(size, '\0');
        uint64_t reencryted_partial_decryption_result_size =
            reencryted_partial_decryption_result.size();
        std::memcpy(result.data(), &reencryted_partial_decryption_result_size,
                    sizeof(uint64_t));

        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (
            size_t i = 0; i < reencryted_partial_decryption_result.size();
            ++i) {
            std::memcpy(result.data() + (i + 1) * 8, &offsets[i],
                        sizeof(uint64_t));
            std::memcpy(result.data() + offsets[i],
                        reencryted_partial_decryption_result[i].data(),
                        reencryted_partial_decryption_result[i].size());
        }
        return result;
    }

    static std::vector<ReencrytedMessage>
    from_string_to_reencrypted_message_for_tensor(const std::string& str) {
        uint64_t num_messages;
        std::memcpy(&num_messages, str.data(), sizeof(uint64_t));
        std::vector<ReencrytedMessage> result(num_messages);
        std::vector<uint64_t> offsets(num_messages);
        for (size_t i = 0; i < num_messages; ++i) {
            std::memcpy(&offsets[i], str.data() + (i + 1) * 8,
                        sizeof(uint64_t));
        }
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < num_messages - 1; ++i) {
            result[i] = str.substr(offsets[i], offsets[i + 1] - offsets[i]);
        }
        result.back() = str.substr(offsets.back());
        return result;
    }
};
} // namespace CoFHE

#endif // COFHE_RSA_REENCRYPTION_HPP_INCLUDED