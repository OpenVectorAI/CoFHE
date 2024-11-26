#ifndef CoFHE_COMPUTE_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_COMPUTE_REQUEST_HANDLER_HPP_INCLUDED

#include <string>
#include <vector>
#include <sstream>

#include "smpc/smpc_client.hpp"
#include "smpc/ciphertext_multiplications.hpp"
#include "node/network_details.hpp"

namespace CoFHE
{
    class ComputeResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        ComputeResponse(Status status, std::string data) : status_m(status), data_m(data) {}

        Status &status() { return status_m; }
        const Status &status() const { return status_m; }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_m.size()) + "\n" + data_m;
        }

        static ComputeResponse from_string(const std::string &str)
        {
            std::istringstream iss(str);
            std::string line;
            std::getline(iss, line);
            std::istringstream iss_line(line);
            int status;
            size_t data_size;
            iss_line >> status >> data_size;
            std::string data = str.substr(line.size() + 1);
            if (data.size() != data_size)
            {
                throw std::runtime_error("Data size mismatch");
            }
            return ComputeResponse(static_cast<Status>(status), data);
        }

    private:
        Status status_m;
        std::string data_m;
    };

    class ComputeRequest
    {
    public:
        using ResponseType = ComputeResponse;
        enum class ComputeOperationType
        {
            UNARY,
            BINARY,
            TERNARY,
        };
        enum class ComputeOperation
        {
            DECRYPT,
            ADD,
            SUBTRACT,
            MULTIPLY,
            DIVIDE,
            // POLYNOMIAL_EVALUATION,
            // SMPC
        };

        enum class DataType
        {
            SINGLE,
            TENSOR,
            TENSOR_ID, // data encryption type will be ignored if tensor id is used
        };

        enum class DataEncrytionType
        {
            PLAINTEXT,
            CIPHERTEXT,
        };

        class ComputeOperationOperand
        {
        public:
            ComputeOperationOperand(DataType data_type, DataEncrytionType encryption_type, std::string data) : data_type_m(data_type), encryption_type_m(encryption_type), data_m(data) {}

            DataType &data_type() { return data_type_m; }
            const DataType &data_type() const { return data_type_m; }
            DataEncrytionType &encryption_type() { return encryption_type_m; }
            const DataEncrytionType &encryption_type() const { return encryption_type_m; }
            std::string &data() { return data_m; }
            const std::string &data() const { return data_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(data_type_m)) + " " + std::to_string(static_cast<int>(encryption_type_m)) + " " + std::to_string(data_m.size()) + "\n" + data_m + "\n";
            }

            static ComputeOperationOperand from_string(const std::string &str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int data_type, encryption_type;
                size_t data_size;
                iss >> data_type >> encryption_type >> data_size;
                std::string data = str.substr(line.size() + 1, data_size);
                if (data.size() != data_size)
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return ComputeOperationOperand(static_cast<DataType>(data_type), static_cast<DataEncrytionType>(encryption_type), data);
            }

            static std::vector<ComputeOperationOperand> from_string(const std::string &str, size_t num_operands)
            {
                std::istringstream iss(str);
                std::vector<ComputeOperationOperand> operands;
                for (size_t i = 0; i < num_operands; i++)
                {
                    std::string operand_str_1;
                    std::getline(iss, operand_str_1);
                    iss >> std::ws;
                    int data_type, encryption_type;
                    size_t data_size;
                    std::istringstream iss_line(operand_str_1);
                    iss_line >> data_type >> encryption_type >> data_size;
                    // get the next data_size chars
                    std::string data = str.substr(iss.tellg(), data_size);
                    iss.seekg(data_size, std::ios_base::cur);
                    iss >> std::ws;
                    operands.push_back(ComputeOperationOperand(static_cast<DataType>(data_type), static_cast<DataEncrytionType>(encryption_type), data));
                }
                return operands;
            };

        private:
            DataType data_type_m;
            DataEncrytionType encryption_type_m;
            std::string data_m;
        };

        class ComputeOperationInstance
        {
        public:
            ComputeOperationInstance(const ComputeOperationType &operation_type,
                                     const ComputeOperation &operation,
                                     const std::vector<ComputeOperationOperand> &operands) : operation_type_m(operation_type), operation_m(operation),
                                                                                             operands_m(operands) {}

            ComputeOperationType &operation_type() { return operation_type_m; }
            const ComputeOperationType &operation_type() const { return operation_type_m; }
            ComputeOperation &operation() { return operation_m; }
            const ComputeOperation &operation() const { return operation_m; }
            std::vector<ComputeOperationOperand> &operands() { return operands_m; }
            const std::vector<ComputeOperationOperand> &operands() const { return operands_m; }

            std::string to_string() const
            {
                std::string str = std::to_string(static_cast<int>(operation_type_m)) + " " + std::to_string(static_cast<int>(operation_m)) + " " +
                                  std::to_string(operands_m.size()) + "\n";
                for (const auto &operand : operands_m)
                {
                    str += operand.to_string();
                }
                return str;
            }

            static ComputeOperationInstance from_string(const std::string &str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int operation_type, operation;
                size_t num_operands;
                iss_line >> operation_type >> operation >> num_operands;
                std::string operands_str = str.substr(line.size() + 1);
                std::vector<ComputeOperationOperand> operands = ComputeOperationOperand::from_string(operands_str, num_operands);
                return ComputeOperationInstance(static_cast<ComputeOperationType>(operation_type), static_cast<ComputeOperation>(operation), operands);
            }

        private:
            ComputeOperationType operation_type_m;
            ComputeOperation operation_m;
            std::vector<ComputeOperationOperand> operands_m;
        };

        ComputeRequest(const ComputeOperationInstance &operation) : operation_m(operation) {}

        ComputeOperationInstance &operation() { return operation_m; }
        const ComputeOperationInstance &operation() const { return operation_m; }

        std::string to_string() const
        {
            return operation_m.to_string();
        }

        static ComputeRequest from_string(const std::string &str)
        {
            ComputeOperationInstance operation = ComputeOperationInstance::from_string(str);
            return ComputeRequest(operation);
        }

    private:
        ComputeOperationInstance operation_m;
    };

    template <typename CryptoSystem>
    class ComputeRequestHandler
    {
    public:
        using RequestType = ComputeRequest;
        using ResponseType = ComputeResponse;
        using CipherText = typename CryptoSystem::CipherText;
        using PlainText = typename CryptoSystem::PlainText;
        ComputeRequestHandler(const NetworkDetails &nd) : nd_m(nd), crypto_system_m(nd_m.cryptosystem_details().security_level, nd_m.cryptosystem_details().k), public_key_m(crypto_system_m.deserialize_public_key(nd_m.cryptosystem_details().public_key)), smpc_client_m(nd_m), ciphertext_multiplier_m(smpc_client_m)
        {
        }

        ComputeRequestHandler(ComputeRequestHandler &&other) : nd_m(other.nd_m), crypto_system_m(other.crypto_system_m), public_key_m(other.public_key_m), smpc_client_m(std::move(other.smpc_client_m)), ciphertext_multiplier_m(smpc_client_m)
        {
        }

        ComputeRequestHandler &operator=(ComputeRequestHandler &&other)
        {
            if (this != &other)
            {
                nd_m = other.nd_m;
                crypto_system_m = other.crypto_system_m;
                public_key_m = other.public_key_m;
                smpc_client_m = std::move(other.smpc_client_m);
                ciphertext_multiplier_m = smpc_client_m;
            }
            return *this;
        }

        ComputeResponse handle_request(const ComputeRequest &req)
        {
            try
            {
                switch (req.operation().operation_type())
                {
                case ComputeRequest::ComputeOperationType::UNARY:
                    return handle_unary_operation(req.operation());
                case ComputeRequest::ComputeOperationType::BINARY:
                    return handle_binary_operation(req.operation());
                case ComputeRequest::ComputeOperationType::TERNARY:
                    return handle_ternary_operation(req.operation());
                default:
                    return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid operation type");
                }
            }
            catch (const std::exception &e)
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
            }
        }

    private:
        NetworkDetails nd_m;
        CryptoSystem crypto_system_m;
        typename CryptoSystem::PublicKey public_key_m;
        SMPCClient<CryptoSystem> smpc_client_m;
        SMPCCipherTextMultiplier<CryptoSystem> ciphertext_multiplier_m;

        ComputeResponse handle_unary_operation(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands().size() != 1)
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, "Unary operation requires 1 operand");
            }
            // convert to binary version and call handle_binary_operation
            switch (operation.operation())
            {
            case ComputeRequest::ComputeOperation::DECRYPT:
                return handle_decrypt(operation);
            default:
                return ComputeResponse(ComputeResponse::Status::ERROR, "Not implemented");
            }
        }

        ComputeResponse handle_binary_operation(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands().size() != 2)
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, "Addition requires 2 operands");
            }
            if ((operation.operands()[0].data_type() == ComputeRequest::DataType::SINGLE || operation.operands()[1].data_type() == ComputeRequest::DataType::SINGLE) && (operation.operands()[0].data_type() != operation.operands()[1].data_type()))
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, "Data type mismatch. If you want to add a tensor and a single value, convert the single value to tensor");
            }

            if (operation.operands()[0].data_type() == ComputeRequest::DataType::TENSOR_ID || operation.operands()[1].data_type() == ComputeRequest::DataType::TENSOR_ID)
            {
                // tensor id addition
                // this will support operations for tensors stored in network, for operations like private inference on open source models like llama, etc
                // gather the tensor from network and convert the operand to tensor data type
                return ComputeResponse(ComputeResponse::Status::ERROR, "Not implemented");
            }

            switch (operation.operation())
            {
            case ComputeRequest::ComputeOperation::ADD:
                switch (operation.operands()[0].data_type())
                {
                case ComputeRequest::DataType::SINGLE:
                {
                    return handle_single_addition(operation);
                }
                case ComputeRequest::DataType::TENSOR:
                {
                    return handle_tensor_addition(operation);
                }
                default:
                    return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data type");
                }
            case ComputeRequest::ComputeOperation::MULTIPLY:
                switch (operation.operands()[0].data_type())
                {
                case ComputeRequest::DataType::SINGLE:
                {
                    return handle_single_multiplication(operation);
                }
                case ComputeRequest::DataType::TENSOR:
                {
                    return handle_tensor_multiplication(operation);
                }
                default:
                    return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data type");
                }
            case ComputeRequest::ComputeOperation::SUBTRACT:
            case ComputeRequest::ComputeOperation::DIVIDE:
                return ComputeResponse(ComputeResponse::Status::ERROR, "Not implemented");
            default:
                return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid operation type");
            }
        }

        ComputeResponse handle_ternary_operation(const ComputeRequest::ComputeOperationInstance &operation)
        {
            // to support conditional evaluation
            return ComputeResponse(ComputeResponse::Status::ERROR, "Not implemented");
        }

        ComputeResponse handle_single_addition(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    return ComputeResponse(ComputeResponse::Status::OK,
                                           crypto_system_m.serialize_ciphertext(
                                               crypto_system_m.add_ciphertexts(public_key_m, crypto_system_m.deserialize_ciphertext(operation.operands()[0].data()), crypto_system_m.deserialize_ciphertext(operation.operands()[1].data()))));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    auto c1 = crypto_system_m.encrypt(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[0].data()));
                    auto c2 = crypto_system_m.encrypt(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[1].data()));
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.add_ciphertexts(public_key_m, c1, c2)));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    auto c1 = crypto_system_m.deserialize_ciphertext(operation.operands()[0].data());
                    auto c2 = crypto_system_m.encrypt(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[1].data()));
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.add_ciphertexts(public_key_m, c1, c2)));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    auto c1 = crypto_system_m.encrypt(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[0].data()));
                    auto c2 = crypto_system_m.deserialize_ciphertext(operation.operands()[1].data());
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.add_ciphertexts(public_key_m, c1, c2)));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }

            return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data encryption type");
        }

        ComputeResponse handle_tensor_addition(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    auto ct1 = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[0].data());
                    auto ct2 = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[1].data());
                    auto res = crypto_system_m.add_ciphertext_tensors(public_key_m, ct1, ct2);
                    auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                    clear_ciphertext_tensors(ct1, ct2, res);
                    return ComputeResponse(ComputeResponse::Status::OK, res_data);
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }

            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    auto pt1 = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[0].data());
                    auto pt2 = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[1].data());
                    auto res = crypto_system_m.add_plaintext_tensors(pt1, pt2);
                    auto res_enc = crypto_system_m.encrypt_tensor(public_key_m, res);
                    auto res_data = crypto_system_m.serialize_ciphertext_tensor(res_enc);
                    clear_plaintext_tensors(pt1, pt2, res_enc);
                    clear_plaintext_tensor(res);
                    return ComputeResponse(ComputeResponse::Status::OK, res_data);
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }

            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                auto ct = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[0].data());
                auto pt = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[1].data());
                auto pt_enc = crypto_system_m.encrypt_tensor(public_key_m, pt);
                auto res = crypto_system_m.add_ciphertext_tensors(public_key_m, ct, pt_enc);
                auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                clear_plaintext_ciphertext_tensors(pt, ct, res);
                clear_ciphertext_tensor(pt_enc);
                return ComputeResponse(ComputeResponse::Status::OK, res_data);
            }

            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                auto pt = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[0].data());
                auto pt_enc = crypto_system_m.encrypt_tensor(public_key_m, pt);
                auto ct = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[1].data());
                auto res = crypto_system_m.add_ciphertext_tensors(public_key_m, ct, pt_enc);
                auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                clear_plaintext_ciphertext_tensors(pt, ct, res);
                clear_ciphertext_tensor(pt_enc);
                return ComputeResponse(ComputeResponse::Status::OK, res_data);
            }
            return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data encryption type");
        }

        ComputeResponse handle_single_multiplication(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    return ComputeResponse(ComputeResponse::Status::OK,
                                           crypto_system_m.serialize_ciphertext(
                                               ciphertext_multiplier_m.multiply_ciphertexts(crypto_system_m.deserialize_ciphertext(operation.operands()[0].data()), crypto_system_m.deserialize_ciphertext(operation.operands()[1].data()))));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.encrypt(public_key_m, crypto_system_m.multiply_plaintexts(crypto_system_m.deserialize_plaintext(operation.operands()[0].data()), crypto_system_m.deserialize_plaintext(operation.operands()[1].data())))));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.scal_ciphertext(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[1].data()), crypto_system_m.deserialize_ciphertext(operation.operands()[0].data()))));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_ciphertext(crypto_system_m.scal_ciphertext(public_key_m, crypto_system_m.deserialize_plaintext(operation.operands()[0].data()), crypto_system_m.deserialize_ciphertext(operation.operands()[1].data()))));
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data encryption type");
        }

        ComputeResponse handle_tensor_multiplication(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    auto des_ct1 = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[0].data());
                    auto des_ct2 = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[1].data());
                    auto res = ciphertext_multiplier_m.multiply_ciphertext_tensors(des_ct1, des_ct2);
                    auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                    clear_ciphertext_tensor(des_ct1);
                    clear_ciphertext_tensor(des_ct2);
                    clear_ciphertext_tensor(res);
                    return ComputeResponse(ComputeResponse::Status::OK, res_data);
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                auto pt1 = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[0].data());
                auto pt2 = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[1].data());
                auto res = crypto_system_m.multiply_plaintext_tensors(pt1, pt2);
                auto res_enc = crypto_system_m.encrypt_tensor(public_key_m, res);
                auto res_data = crypto_system_m.serialize_ciphertext_tensor(res_enc);
                clear_plaintext_tensor(pt1);
                clear_plaintext_tensor(pt2);
                clear_plaintext_tensor(res);
                clear_ciphertext_tensor(res_enc);
                return ComputeResponse(ComputeResponse::Status::OK, res_data);
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT)
            {
                try
                {
                    auto des_ct = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[0].data());
                    auto des_sc = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[1].data());
                    auto res = crypto_system_m.scal_ciphertext_tensors(public_key_m, des_sc, des_ct);
                    auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                    clear_plaintext_tensor(des_sc);
                    clear_ciphertext_tensor(des_ct);
                    clear_ciphertext_tensor(res);
                    return ComputeResponse(ComputeResponse::Status::OK, res_data);
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            if (operation.operands()[0].encryption_type() == ComputeRequest::DataEncrytionType::PLAINTEXT && operation.operands()[1].encryption_type() == ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                try
                {
                    auto des_sc = crypto_system_m.deserialize_plaintext_tensor(operation.operands()[0].data());
                    auto des_ct = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[1].data());
                    auto res = crypto_system_m.scal_ciphertext_tensors(public_key_m, des_sc, des_ct);
                    auto res_data = crypto_system_m.serialize_ciphertext_tensor(res);
                    clear_plaintext_tensor(des_sc);
                    clear_ciphertext_tensor(des_ct);
                    clear_ciphertext_tensor(res);
                    return ComputeResponse(ComputeResponse::Status::OK, res_data);
                }
                catch (const std::exception &e)
                {
                    return ComputeResponse(ComputeResponse::Status::ERROR, e.what());
                }
            }
            return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data encryption type");
        }

        ComputeResponse handle_decrypt(const ComputeRequest::ComputeOperationInstance &operation)
        {
            if (operation.operands()[0].encryption_type() != ComputeRequest::DataEncrytionType::CIPHERTEXT)
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data encryption type");
            }
            switch (operation.operands()[0].data_type())
            {
            case ComputeRequest::DataType::SINGLE:
            {
                auto ct = crypto_system_m.deserialize_ciphertext(operation.operands()[0].data());
                auto pt = smpc_client_m.decrypt(ct);
                return ComputeResponse(ComputeResponse::Status::OK, crypto_system_m.serialize_plaintext(pt));
            }
            case ComputeRequest::DataType::TENSOR:
            {
                auto ct = crypto_system_m.deserialize_ciphertext_tensor(operation.operands()[0].data());
                auto pt = smpc_client_m.decrypt_tensor(ct);
                auto res_data = crypto_system_m.serialize_plaintext_tensor(pt);
                clear_ciphertext_tensor(ct);
                clear_plaintext_tensor(pt);
                return ComputeResponse(ComputeResponse::Status::OK, res_data);
            }
            case ComputeRequest::DataType::TENSOR_ID:
            {
                return ComputeResponse(ComputeResponse::Status::ERROR, "Not implemented");
            }
            default:
                return ComputeResponse(ComputeResponse::Status::ERROR, "Invalid data type");
            }
        }

        void clear_ciphertext_tensors(Tensor<CipherText *> &ct1, Tensor<CipherText *> &ct2, Tensor<CipherText *> &res)
        {
            ct1.flatten();
            ct2.flatten();
            res.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < ct1.num_elements(); i++)
            {
                delete ct1.at(i);
                delete ct2.at(i);
                delete res.at(i);
            }
        }

        void clear_plaintext_tensors(Tensor<PlainText *> &pt1, Tensor<PlainText *> &pt2, Tensor<CipherText *> &res)
        {
            pt1.flatten();
            pt2.flatten();
            res.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < pt1.num_elements(); i++)
            {
                delete pt1.at(i);
                delete pt2.at(i);
                delete res.at(i);
            }
        }

        void clear_plaintext_tensor(Tensor<PlainText *> &pt)
        {
            pt.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < pt.num_elements(); i++)
            {
                delete pt.at(i);
            }
        }

        void clear_ciphertext_tensor(Tensor<CipherText *> &ct)
        {
            ct.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < ct.num_elements(); i++)
            {
                delete ct.at(i);
            }
        }

        void clear_plaintext_ciphertext_tensors(Tensor<PlainText *> &pt, Tensor<CipherText *> &ct, Tensor<CipherText *> &res)
        {
            pt.flatten();
            ct.flatten();
            res.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < pt.num_elements(); i++)
            {
                delete pt.at(i);
                delete ct.at(i);
                delete res.at(i);
            }
        }
    };
} // namespace CoFHE

#endif