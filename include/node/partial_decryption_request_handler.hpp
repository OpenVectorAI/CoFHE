#ifndef CoFHE_PARTIAL_DECRYPTION_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_PARTIAL_DECRYPTION_REQUEST_HANDLER_HPP_INCLUDED

#include <sstream>
#include <string>
#include <vector>

#include "smpc/reencryption.hpp"

namespace CoFHE {
class PartialDecryptionResponse {
  public:
    enum class Status {
        OK,
        ERROR,
    };

    PartialDecryptionResponse(Status status, std::string data)
        : status_m(status), data_m(data) {}

    Status& status() { return status_m; }
    const Status& status() const { return status_m; }
    std::string& data() { return data_m; }
    const std::string& data() const { return data_m; }

    std::string to_string() const {
        return std::to_string(static_cast<int>(status_m)) + " " +
               std::to_string(data_m.size()) + "\n" + data_m;
    }

    static PartialDecryptionResponse from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string line;
        std::getline(iss, line);
        std::istringstream iss_line(line);
        int status;
        size_t data_size;
        iss_line >> status >> data_size;
        std::string data = str.substr(line.size() + 1);
        if (data.size() != data_size) {
            throw std::runtime_error("Data size mismatch");
        }
        return PartialDecryptionResponse(static_cast<Status>(status), data);
    }

  private:
    Status status_m;
    std::string data_m;
};

class PartialDecryptionRequest {
  public:
    using ResponseType = PartialDecryptionResponse;
    enum class DataType {
        SINGLE,
        TENSOR,
        TENSOR_ID,
    };
    enum class DataEncryptionType {
        REENCRYPTION,
        NONE,
    };
    PartialDecryptionRequest(size_t sk_share_id, DataType data_type,
                             std::string data)
        : sk_share_id_m(sk_share_id), data_type_m(data_type),
          data_encryption_type_m(DataEncryptionType::NONE),
          serialized_public_key_m(""), data_m(data) {}
    PartialDecryptionRequest(size_t sk_share_id, DataType data_type,
                             DataEncryptionType data_encryption_type,
                             std::string serialized_public_key,
                             std::string data)
        : sk_share_id_m(sk_share_id), data_type_m(data_type),
          data_encryption_type_m(data_encryption_type),
          serialized_public_key_m(serialized_public_key), data_m(data) {}

    size_t& sk_share_id() { return sk_share_id_m; }
    const size_t& sk_share_id() const { return sk_share_id_m; }
    DataType& data_type() { return data_type_m; }
    const DataType& data_type() const { return data_type_m; }
    DataEncryptionType& data_encryption_type() {
        return data_encryption_type_m;
    }
    const DataEncryptionType& data_encryption_type() const {
        return data_encryption_type_m;
    }
    std::string& serialized_public_key() { return serialized_public_key_m; }
    const std::string& serialized_public_key() const {
        return serialized_public_key_m;
    }
    std::string& data() { return data_m; }
    const std::string& data() const { return data_m; }

    std::string to_string() const {
        return std::to_string(sk_share_id_m) + " " +
               std::to_string(static_cast<int>(data_type_m)) + " " +
               std::to_string(static_cast<int>(data_encryption_type_m)) + " " +
               std::to_string(serialized_public_key_m.size()) + " " +
               std::to_string(data_m.size()) + "\n" + serialized_public_key_m +
               data_m;
    }

    static PartialDecryptionRequest from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string line;
        std::getline(iss, line);
        std::istringstream iss_line(line);
        int data_type, data_encryption_type;
        size_t sk_share_id, data_size, serialized_public_key_size;
        iss_line >> sk_share_id >> data_type >> data_encryption_type >>
            serialized_public_key_size >> data_size;
        std::string serialized_public_key =
            str.substr(line.size() + 1, serialized_public_key_size);
        std::string data =
            str.substr(line.size() + 1 + serialized_public_key_size);
        if (data.size() != data_size) {
            throw std::runtime_error("Data size mismatch");
        }
        return PartialDecryptionRequest(
            sk_share_id, static_cast<DataType>(data_type),
            static_cast<DataEncryptionType>(data_encryption_type),
            serialized_public_key, data);
    }

  private:
    size_t sk_share_id_m;
    DataType data_type_m;
    DataEncryptionType data_encryption_type_m;
    std::string serialized_public_key_m;
    std::string data_m;
};

template <typename CryptoSystem, typename PKCEncryptor>
class PartialDecryptionRequestHandler {
  public:
    using RequestType = PartialDecryptionRequest;
    using ResponseType = PartialDecryptionResponse;
    using SecretKeyShare = typename CryptoSystem::SecretKeyShare;
    using CipherText = typename CryptoSystem::CipherText;
    using PlainText = typename CryptoSystem::PlainText;
    using Reencryptor =
        PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>;
    using ReencryptionKeyPair = typename Reencryptor::ReencryptionKeyPair;
    using ReencrytedMessage = typename Reencryptor::ReencrytedMessage;

    PartialDecryptionRequestHandler(
        const CryptoSystem& crypto_system,
        const std::vector<SecretKeyShare>& secret_key_shares,
        const PKCEncryptor& encryptor)
        : cryptosystem_m(crypto_system), secret_key_shares_m(secret_key_shares),
          reencryptor_m(encryptor, crypto_system) {}

    PartialDecryptionResponse
    handle_request(const PartialDecryptionRequest& request) const {
        if (request.sk_share_id() >= secret_key_shares_m.size()) {
            return PartialDecryptionResponse(
                PartialDecryptionResponse::Status::ERROR,
                "Invalid secret key share id");
        }
        switch (request.data_encryption_type()) {
        case PartialDecryptionRequest::DataEncryptionType::NONE: {
            switch (request.data_type()) {
            case PartialDecryptionRequest::DataType::SINGLE:
                return handle_single_value(request);
            case PartialDecryptionRequest::DataType::TENSOR:
                return handle_tensor(request);
            case PartialDecryptionRequest::DataType::TENSOR_ID:
                return handle_tensor_id(request);
            default:
                return PartialDecryptionResponse(
                    PartialDecryptionResponse::Status::ERROR,
                    "Invalid data type");
            }
        }
        case PartialDecryptionRequest::DataEncryptionType::REENCRYPTION: {
            switch (request.data_type()) {
            case PartialDecryptionRequest::DataType::SINGLE:
                return handle_single_value_with_reencryption(request);
            case PartialDecryptionRequest::DataType::TENSOR:
                return handle_tensor_with_reencryption(request);
            case PartialDecryptionRequest::DataType::TENSOR_ID:
                return handle_tensor_id_with_reencryption(request);
            default:
                return PartialDecryptionResponse(
                    PartialDecryptionResponse::Status::ERROR,
                    "Invalid data type");
            }
        }
        default:
            return PartialDecryptionResponse(
                PartialDecryptionResponse::Status::ERROR,
                "Invalid data encryption type");
        }
    }

    void set_secret_key_shares(
        const std::vector<SecretKeyShare>& secret_key_shares) {
        secret_key_shares_m = secret_key_shares;
    }

  private:
    CryptoSystem cryptosystem_m;
    std::vector<SecretKeyShare> secret_key_shares_m;
    Reencryptor reencryptor_m;

    PartialDecryptionResponse
    handle_single_value(const PartialDecryptionRequest& request) const {
        return PartialDecryptionResponse(
            PartialDecryptionResponse::Status::OK,
            cryptosystem_m.serialize_partial_decryption_result(
                cryptosystem_m.part_decrypt(
                    secret_key_shares_m[request.sk_share_id()],
                    cryptosystem_m.deserialize_ciphertext(request.data()))));
    }

    PartialDecryptionResponse
    handle_tensor(const PartialDecryptionRequest& request) const {
        auto des_ct =
            cryptosystem_m.deserialize_ciphertext_tensor(request.data());
        auto res = cryptosystem_m.part_decrypt_tensor(
            secret_key_shares_m[request.sk_share_id()], des_ct);
        auto res_data =
            cryptosystem_m.serialize_partial_decryption_result_tensor(res);
        des_ct.flatten();
        res.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < des_ct.num_elements();
                                                i++) {
            delete des_ct.at(i);
            delete res.at(i);
        }
        return PartialDecryptionResponse(PartialDecryptionResponse::Status::OK,
                                         res_data);
    }

    PartialDecryptionResponse
    handle_tensor_id(const PartialDecryptionRequest& request) const {
        // get the data from the network and use handle_tensor
        return PartialDecryptionResponse(
            PartialDecryptionResponse::Status::ERROR, "Not implemented");
    }

    PartialDecryptionResponse handle_single_value_with_reencryption(
        const PartialDecryptionRequest& request) const {
        return PartialDecryptionResponse(
            PartialDecryptionResponse::Status::OK,
            reencryptor_m.reencrypt(
                cryptosystem_m.part_decrypt(
                    secret_key_shares_m[request.sk_share_id()],
                    cryptosystem_m.deserialize_ciphertext(request.data())),
                request.serialized_public_key()));
    }

    PartialDecryptionResponse handle_tensor_with_reencryption(
        const PartialDecryptionRequest& request) const {
        auto des_ct =
            cryptosystem_m.deserialize_ciphertext_tensor(request.data());
        auto pdr = cryptosystem_m.part_decrypt_tensor(
            secret_key_shares_m[request.sk_share_id()], des_ct);
        auto res = PartialDecryptionResponse(
            PartialDecryptionResponse::Status::OK,
            reencryptor_m.reencrypt_tensor(pdr,
                                           request.serialized_public_key()));
        des_ct.flatten();
        pdr.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < des_ct.num_elements();
                                                i++) {
            delete des_ct.at(i);
            delete pdr.at(i);
        }
        return res;
    }

    PartialDecryptionResponse handle_tensor_id_with_reencryption(
        const PartialDecryptionRequest& request) const {
        // get the data from the network and use handle_tensor
        return PartialDecryptionResponse(
            PartialDecryptionResponse::Status::ERROR, "Not implemented");
    }
};

} // namespace CoFHE

#endif