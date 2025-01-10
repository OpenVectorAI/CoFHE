#ifndef CoFHE_COMPUTE_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_COMPUTE_REQUEST_HANDLER_HPP_INCLUDED

#include <string>
#include <vector>
#include <sstream>

#include "smpc/smpc_client.hpp"
#include "smpc/ciphertext_multiplications.hpp"
#include "node/network_details.hpp"
#include "node/compute_request_response.hpp"

namespace CoFHE
{

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

            // if (operation.operation() == ComputeRequest::ComputeOperation::REENCRYPT)
            // {
            //     return handle_reencrypt(operation);
            // }
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
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct1.num_elements(); i++)
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
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt1.num_elements(); i++)
            {
                delete pt1.at(i);
                delete pt2.at(i);
                delete res.at(i);
            }
        }

        void clear_plaintext_tensor(Tensor<PlainText *> &pt)
        {
            pt.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt.num_elements(); i++)
            {
                delete pt.at(i);
            }
        }

        void clear_ciphertext_tensor(Tensor<CipherText *> &ct)
        {
            ct.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct.num_elements(); i++)
            {
                delete ct.at(i);
            }
        }

        void clear_plaintext_ciphertext_tensors(Tensor<PlainText *> &pt, Tensor<CipherText *> &ct, Tensor<CipherText *> &res)
        {
            pt.flatten();
            ct.flatten();
            res.flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt.num_elements(); i++)
            {
                delete pt.at(i);
                delete ct.at(i);
                delete res.at(i);
            }
        }
    };
} // namespace CoFHE

#endif