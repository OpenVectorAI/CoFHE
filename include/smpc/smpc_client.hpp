#ifndef COFHE_SMPC_CLIENT_HPP_INCLUDED
#define COFHE_SMPC_CLIENT_HPP_INCLUDED

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "node/beavers_triplet_request_handler.hpp"
#include "node/client.hpp"
#include "node/cofhe_node_request_handler.hpp"
#include "node/network_details.hpp"
#include "node/network_details_request_handler.hpp"
#include "node/partial_decryption_request_handler.hpp"
#include "node/setup_node_request_handler.hpp"
#include "smpc/reencryption.hpp"

#define BEAVERS_TRIPLET_CACHE_SIZE 10000  // 1000000
#define COMPARISION_PAIR_CACHE_SIZE 2500 // 250000

namespace CoFHE {
template <typename CryptoSystem, typename PKCEncryptor,
          typename SHECryptoSystem>
class SMPCClient {
  public:
    using PlainText = typename CryptoSystem::PlainText;
    using CipherText = typename CryptoSystem::CipherText;
    using PartialDecryptionResult =
        typename CryptoSystem::PartialDecryptionResult;

    SMPCClient(const NetworkDetails& nd,
               const BeaversTripletGenerationDetails& beavers_triplet_details,
               const ComparisionPairGenerationDetails& comparision_pair_details)
        : network_details_m(nd),
          beavers_triplet_threshold_m(beavers_triplet_details.threshold()),
          crypto_system_m(CryptoSystem(
              network_details_m.cryptosystem_details().security_level,
              network_details_m.cryptosystem_details().k,
              network_details_m.cryptosystem_details().N)),
          public_key_m(crypto_system_m.deserialize_public_key(
              network_details_m.cryptosystem_details().public_key)),
          beavers_triplet_generator_m(crypto_system_m, public_key_m,
                                      beavers_triplet_details),
          comparision_pair_generator_m(crypto_system_m, public_key_m,
                                       comparision_pair_details) {
        init();
    }

    SMPCClient(SMPCClient&& other)
        : network_details_m(other.network_details_m),
          beavers_triplet_threshold_m(other.beavers_triplet_threshold_m),
          crypto_system_m(other.crypto_system_m),
          public_key_m(other.public_key_m),
          beavers_triplet_generator_m(
              std::move(other.beavers_triplet_generator_m)),
          comparision_pair_generator_m(
              std::move(other.comparision_pair_generator_m)) {
        std::lock_guard<std::mutex> lock(other.beavers_triplets_mutex_m);
        std::lock_guard<std::mutex> lock2(other.comparision_pairs_mutex_m);
        clients_cofhe_node_m = std::move(other.clients_cofhe_node_m);
        client_trusted_node_m = std::move(other.client_trusted_node_m);
        beavers_triplets_m = std::move(other.beavers_triplets_m);
        beavers_triplets_index_m = other.beavers_triplets_index_m;
        comparision_pairs_m = std::move(other.comparision_pairs_m);
        comparision_pairs_index_m = other.comparision_pairs_index_m;
        part_decryption_index_m = other.part_decryption_index_m;
    }

    SMPCClient& operator=(SMPCClient&& other) {
        if (this != &other) {
            std::lock_guard<std::mutex> lock(other.beavers_triplets_mutex_m);
            std::lock_guard<std::mutex> lock2(other.comparision_pairs_mutex_m);
            network_details_m = other.network_details_m;
            beavers_triplet_threshold_m = other.beavers_triplet_threshold_m;
            crypto_system_m = other.crypto_system_m;
            public_key_m = other.public_key_m;
            clients_cofhe_node_m = std::move(other.clients_cofhe_node_m);
            client_trusted_node_m = std::move(other.client_trusted_node_m);
            beavers_triplets_m = std::move(other.beavers_triplets_m);
            beavers_triplets_index_m = other.beavers_triplets_index_m;
            comparision_pairs_m = std::move(other.comparision_pairs_m);
            comparision_pairs_index_m = other.comparision_pairs_index_m;
            part_decryption_index_m = other.part_decryption_index_m;
            beavers_triplet_generator_m =
                std::move(other.beavers_triplet_generator_m);
            comparision_pair_generator_m =
                std::move(other.comparision_pair_generator_m);
        }
        return *this;
    }

    Tensor<CipherText*> get_beavers_triplets(size_t size) {
        if (client_trusted_node_m == nullptr) {
            throw std::runtime_error("Trusted node not found");
        }
        std::lock_guard<std::mutex> lock(beavers_triplets_mutex_m);
        if (beavers_triplets_m.size() - beavers_triplets_index_m >= size) {
            Tensor<CipherText*> triplets(size, 3);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size;
                                                    i++) {
                triplets.at(i, 0) =
                    beavers_triplets_m[beavers_triplets_index_m + i][0];
                triplets.at(i, 1) =
                    beavers_triplets_m[beavers_triplets_index_m + i][1];
                triplets.at(i, 2) =
                    beavers_triplets_m[beavers_triplets_index_m + i][2];
            }
            beavers_triplets_index_m += size;
            return triplets;
        } else {
            auto beavers_triplet_randomness_request = CoFHENodeRequest(
                CoFHENodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST,
                BeaversTripletRequest(
                    BeaversTripletRequest::RequestType::
                        BEAVERS_TRIPLET_CONVERSION_RANDOMNESS_REQUEST,
                    size + BEAVERS_TRIPLET_CACHE_SIZE -
                        (beavers_triplets_m.size() - beavers_triplets_index_m))
                    .to_string());

            std::vector<CoFHE::CoFHENodeResponse*> randomness_res(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                clients_cofhe_node_m[i]->run(
                    Network::ServiceType::COFHE_REQUEST,
                    beavers_triplet_randomness_request, &randomness_res[i]);
            }
            std::vector<std::string> randomness_data(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                if (randomness_res[i]->header().status() !=
                    CoFHENodeResponse::Status::OK) {
                    throw std::runtime_error("Partial decryption failed");
                }
                auto res = BeaversTripletResponse::from_string(
                    randomness_res[i]->data());
                if (res.status() != BeaversTripletResponse::Status::OK) {
                    throw std::runtime_error("Beavers triplet request failed");
                }
                randomness_data[i] = res.data();
                delete randomness_res[i];
            }
            auto [cs_randomness_tensor, she_randomness_tensor] =
                beavers_triplet_generator_m.accumulate_randomness(
                    randomness_data);

            auto ab_pair_request = CoFHENodeRequest(
                CoFHENodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST,
                BeaversTripletRequest(
                    BeaversTripletRequest::RequestType::
                        BEAVERS_TRIPLET_AB_PAIR_REQUEST,
                    size + BEAVERS_TRIPLET_CACHE_SIZE -
                        (beavers_triplets_m.size() - beavers_triplets_index_m))
                    .to_string());
            std::vector<CoFHE::CoFHENodeResponse*> ab_pair_res(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                clients_cofhe_node_m[i]->run(
                    Network::ServiceType::COFHE_REQUEST, ab_pair_request,
                    &ab_pair_res[i]);
            }
            std::vector<std::string> ab_pairs_in_res(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                if (ab_pair_res[i]->header().status() !=
                    CoFHENodeResponse::Status::OK) {
                    throw std::runtime_error("Partial decryption failed");
                }
                auto res =
                    BeaversTripletResponse::from_string(ab_pair_res[i]->data());
                if (res.status() != BeaversTripletResponse::Status::OK) {
                    throw std::runtime_error("Beavers triplet request failed");
                }
                ab_pairs_in_res[i] = res.data();
                delete ab_pair_res[i];
            }
            auto [serialized_she_triplets_before_conversion,
                  she_triplets_before_conversion] =
                beavers_triplet_generator_m.prepare_pairs_for_conversion(
                    ab_pairs_in_res, she_randomness_tensor);
            auto bg_conv_request = CoFHENodeRequest(
                CoFHENodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST,
                BeaversTripletRequest(
                    BeaversTripletRequest::RequestType::
                        BEAVERS_TRIPLET_CONVERSION_REQUEST,
                    "not_lead\n" + serialized_she_triplets_before_conversion)
                    .to_string());
            auto bg_conv_lead_request = CoFHENodeRequest(
                CoFHENodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST,
                BeaversTripletRequest(
                    BeaversTripletRequest::RequestType::
                        BEAVERS_TRIPLET_CONVERSION_REQUEST,
                    "lead\n" + serialized_she_triplets_before_conversion)
                    .to_string());
            std::vector<CoFHE::CoFHENodeResponse*> bg_conv_res(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                if (i == 0) {
                    clients_cofhe_node_m[i]->run(
                        Network::ServiceType::COFHE_REQUEST,
                        bg_conv_lead_request, &bg_conv_res[i]);
                } else {
                    clients_cofhe_node_m[i]->run(
                        Network::ServiceType::COFHE_REQUEST, bg_conv_request,
                        &bg_conv_res[i]);
                }
            }
            std::vector<std::string> serialized_triplets(
                beavers_triplet_threshold_m);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    beavers_triplet_threshold_m;
                                                    i++) {
                if (bg_conv_res[i]->header().status() !=
                    CoFHENodeResponse::Status::OK) {
                    throw std::runtime_error("Partial decryption failed");
                }
                auto res =
                    BeaversTripletResponse::from_string(bg_conv_res[i]->data());
                if (res.status() != BeaversTripletResponse::Status::OK) {
                    throw std::runtime_error("Beavers triplet request failed");
                }
                serialized_triplets[i] = res.data();
                delete bg_conv_res[i];
            }
            auto res_ = beavers_triplet_generator_m.finalize_beavers_triplets(
                serialized_triplets, she_triplets_before_conversion,
                cs_randomness_tensor);

            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    cs_randomness_tensor.size();
                                                    i++) {
                delete cs_randomness_tensor.at(i, 0);
                delete cs_randomness_tensor.at(i, 1);
                delete cs_randomness_tensor.at(i, 2);
                delete she_randomness_tensor.at(i, 0);
                delete she_randomness_tensor.at(i, 1);
                delete she_randomness_tensor.at(i, 2);
                delete she_triplets_before_conversion.at(i, 0);
                delete she_triplets_before_conversion.at(i, 1);
                delete she_triplets_before_conversion.at(i, 2);
            }

            Tensor<CipherText*> triplets(size, 3);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (
                size_t i = beavers_triplets_index_m;
                i < beavers_triplets_m.size(); i++) {
                triplets.at(i - beavers_triplets_index_m, 0) =
                    beavers_triplets_m[i][0];
                triplets.at(i - beavers_triplets_index_m, 1) =
                    beavers_triplets_m[i][1];
                triplets.at(i - beavers_triplets_index_m, 2) =
                    beavers_triplets_m[i][2];
            }
            size_t curr_req =
                beavers_triplets_m.size() - beavers_triplets_index_m;
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i < size - curr_req; i++) {
                triplets.at(i + curr_req, 0) = res_.at(i, 0);
                triplets.at(i + curr_req, 1) = res_.at(i, 1);
                triplets.at(i + curr_req, 2) = res_.at(i, 2);
            }
            beavers_triplets_index_m = 0;
            beavers_triplets_m.clear();
            for (size_t i = size - curr_req; i < res_.size(); i++) {
                beavers_triplets_m.push_back(
                    {res_.at(i, 0), res_.at(i, 1), res_.at(i, 2)});
            }
            return triplets;
        }
    };

    Tensor<CipherText*> get_comparision_pairs(size_t size) {
        if (client_trusted_node_m == nullptr) {
            throw std::runtime_error("Trusted node not found");
        }
        std::lock_guard<std::mutex> lock(comparision_pairs_mutex_m);
        if (comparision_pairs_m.size() - comparision_pairs_index_m >= size) {
            Tensor<CipherText*> pairs(size, 2);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size;
                                                    i++) {
                pairs.at(i, 0) =
                    comparision_pairs_m[comparision_pairs_index_m + i].first;
                pairs.at(i, 1) =
                    comparision_pairs_m[comparision_pairs_index_m + i].second;
            }
            comparision_pairs_index_m += size;
            return pairs;
        } else {
            auto request = CoFHENodeRequest(
                CoFHENodeRequest::RequestType::COMPARISION_PAIR_REQUEST,
                ComparisionPairRequest(
                    size + COMPARISION_PAIR_CACHE_SIZE -
                    (comparision_pairs_m.size() - comparision_pairs_index_m))
                    .to_string());
            std::vector<CoFHE::CoFHENodeResponse*> res(
                network_details_m.cryptosystem_details().threshold);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                    i++) {
                clients_cofhe_node_m[i]->run(
                    Network::ServiceType::COFHE_REQUEST, request, &res[i]);
            }
            std::vector<Tensor<CipherText*>> pairs_in_res;
            for (size_t i = 0;
                 i < network_details_m.cryptosystem_details().threshold; i++) {
                pairs_in_res.push_back(Tensor<CipherText*>(size, 2));
            }
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i <
                                                    network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                    i++) {
                if (res[i]->header().status() !=
                    CoFHENodeResponse::Status::OK) {
                    throw std::runtime_error("Partial decryption failed");
                }
                auto cp_res =
                    ComparisionPairResponse::from_string(res[i]->data());
                if (cp_res.status() !=
                    ComparisionPairResponse::Status::SUCCESS) {
                    throw std::runtime_error("Comparision pair request failed");
                }
                pairs_in_res[i] = crypto_system_m.deserialize_ciphertext_tensor(
                    cp_res.data());
                delete res[i];
            }

            auto res_ = comparision_pair_generator_m.accumulate(pairs_in_res);
            for (size_t i = 0;
                 i < network_details_m.cryptosystem_details().threshold; i++) {
                pairs_in_res[i].flatten();
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                        j <
                                                        pairs_in_res[i].size();
                                                        j++) {
                    delete pairs_in_res[i].at(j);
                }
            }

            Tensor<CipherText*> pairs(size, 2);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (
                size_t i = comparision_pairs_index_m;
                i < comparision_pairs_m.size(); i++) {
                pairs.at(i - comparision_pairs_index_m, 0) =
                    comparision_pairs_m[i].first;
                pairs.at(i - comparision_pairs_index_m, 1) =
                    comparision_pairs_m[i].second;
            }
            size_t curr_req =
                comparision_pairs_m.size() - comparision_pairs_index_m;
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                    i < size - curr_req; i++) {
                pairs.at(i + curr_req, 0) = res_.at(i, 0);
                pairs.at(i + curr_req, 1) = res_.at(i, 1);
            }
            comparision_pairs_index_m = 0;
            comparision_pairs_m.clear();
            for (size_t i = size - curr_req; i < res_.size(); i++) {
                comparision_pairs_m.push_back({res_.at(i, 0), res_.at(i, 1)});
            }
            return pairs;
        }
    }

    PlainText decrypt(CipherText ct) {
        return crypto_system_m.combine_partial_decryption_results(
            ct, partial_decrypt(ct));
    }

    Tensor<PlainText*> decrypt_tensor(Tensor<CipherText*> ct) {
        auto pdrs = partial_decrypt_tensor(ct);
        auto res =
            crypto_system_m.combine_partial_decryption_results_tensor(ct, pdrs);
        for (size_t i = 0; i < pdrs.size(); ++i) {
            pdrs.at(i).flatten();
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                    j < pdrs.at(i).size();
                                                    j++) {
                delete pdrs.at(i).at(j);
            }
        }
        return res;
    }

    std::string
    reencrypt(const CipherText& ct,
              const std::string& serialized_reencryption_public_key) {
        if (clients_cofhe_node_m.size() <
            network_details_m.cryptosystem_details().threshold) {
            reinit_partial_decryption_clients();
        }
        auto request = CoFHENodeRequest(
            CoFHENodeRequest::RequestType::PartialDecryption,
            PartialDecryptionRequest(
                part_decryption_index_m,
                PartialDecryptionRequest::DataType::SINGLE,
                PartialDecryptionRequest::DataEncryptionType::REENCRYPTION,
                serialized_reencryption_public_key,
                crypto_system_m.serialize_ciphertext(ct))
                .to_string());
        std::vector<CoFHE::CoFHENodeResponse*> res(
            network_details_m.cryptosystem_details().threshold);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            clients_cofhe_node_m[i]->run(Network::ServiceType::COFHE_REQUEST,
                                         request, &res[i]);
        }
        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            if (res[i]->header().status() != CoFHENodeResponse::Status::OK) {
                throw std::runtime_error("Partial decryption failed");
            }
        }
        std::vector<std::string> reencryted_partial_decryption_result(
            network_details_m.cryptosystem_details().threshold);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            reencryted_partial_decryption_result[i] =
                PartialDecryptionResponse::from_string(res[i]->data()).data();
            delete res[i];
        }
        return PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>::
            concatenate_reencrypted_messages(
                reencryted_partial_decryption_result);
    }

    std::string
    reencrypt_tensor(const Tensor<CipherText*>& ct,
                     const std::string& serialized_reencryption_public_key) {
        if (clients_cofhe_node_m.size() <
            network_details_m.cryptosystem_details().threshold) {
            reinit_partial_decryption_clients();
        }
        auto request = CoFHENodeRequest(
            CoFHENodeRequest::RequestType::PartialDecryption,
            PartialDecryptionRequest(
                part_decryption_index_m,
                PartialDecryptionRequest::DataType::TENSOR,
                PartialDecryptionRequest::DataEncryptionType::REENCRYPTION,
                serialized_reencryption_public_key,
                crypto_system_m.serialize_ciphertext_tensor(ct))
                .to_string());
        std::vector<CoFHE::CoFHENodeResponse*> res(
            network_details_m.cryptosystem_details().threshold);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            clients_cofhe_node_m[i]->run(Network::ServiceType::COFHE_REQUEST,
                                         request, &res[i]);
        }
        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            if (res[i]->header().status() != CoFHENodeResponse::Status::OK) {
                throw std::runtime_error("Partial decryption failed");
            }
        }
        std::vector<std::string> reencryted_partial_decryption_result(
            network_details_m.cryptosystem_details().threshold);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            reencryted_partial_decryption_result[i] =
                PartialDecryptionResponse::from_string(res[i]->data()).data();
            delete res[i];
        }
        return PartialDecryptionResultReencryption<PKCEncryptor, CryptoSystem>::
            concatenate_reencrypted_messages(
                reencryted_partial_decryption_result);
    }

    CryptoSystem& crypto_system() { return crypto_system_m; }
    const CryptoSystem& crypto_system() const { return crypto_system_m; }
    typename CryptoSystem::PublicKey& network_public_key() {
        return public_key_m;
    }
    const typename CryptoSystem::PublicKey& network_public_key() const {
        return public_key_m;
    }

  private:
    // reinit_partial_decryption_clients might change it
    mutable NetworkDetails network_details_m;
    size_t beavers_triplet_threshold_m;
    CryptoSystem crypto_system_m;
    typename CryptoSystem::PublicKey public_key_m;
    std::vector<std::unique_ptr<Network::Client>> clients_cofhe_node_m;
    std::unique_ptr<Network::Client> client_trusted_node_m;
    std::mutex beavers_triplets_mutex_m;
    std::vector<std::array<typename CryptoSystem::CipherText*, 3>>
        beavers_triplets_m;
    size_t beavers_triplets_index_m = 0;
    std::mutex comparision_pairs_mutex_m;
    std::vector<std::pair<typename CryptoSystem::CipherText*,
                          typename CryptoSystem::CipherText*>>
        comparision_pairs_m;
    size_t comparision_pairs_index_m = 0;
    size_t part_decryption_index_m = 0;
    BeaversTripletGenerator<CryptoSystem, SHECryptoSystem>
        beavers_triplet_generator_m;
    ComparisionPairGenerator<CryptoSystem> comparision_pair_generator_m;

    void init() {
        // init clients
        clients_cofhe_node_m.clear();
        client_trusted_node_m = nullptr;
        part_decryption_index_m = 0;
        std::vector<size_t> partial_decryption_clients;
        size_t i = 0;
        size_t required_threshold =
            network_details_m.cryptosystem_details().threshold;
        if (required_threshold < beavers_triplet_threshold_m)
            required_threshold = beavers_triplet_threshold_m;
        for (const auto& node : network_details_m.nodes()) {
            try {
                if (node.type == NodeType::CoFHE_NODE) {
                    if (clients_cofhe_node_m.size() < required_threshold) {
                        ++i;
                        clients_cofhe_node_m.push_back(
                            std::make_unique<Network::Client>(node.ip,
                                                              node.port));
                        partial_decryption_clients.push_back(i);
                    }
                } else if (node.type == NodeType::SETUP_NODE &&
                           client_trusted_node_m == nullptr) {
                    client_trusted_node_m =
                        std::make_unique<Network::Client>(node.ip, node.port);
                }
            } catch (const std::exception& e) {
                std::cerr << e.what() << '\n';
            }
            if (clients_cofhe_node_m.size() >= required_threshold &&
                client_trusted_node_m != nullptr) {
                break;
            }
        }
        if (clients_cofhe_node_m.size() < required_threshold) {
            throw std::runtime_error("Not enough partial decryption clients");
        }
        part_decryption_index_m = combinationSequenceNumber(
            network_details_m.cryptosystem_details().total_nodes,
            network_details_m.cryptosystem_details().threshold,
            partial_decryption_clients);

        std::cout << "Partial decryption clients initialized, "
                     "part_decryption_index_m: "
                  << part_decryption_index_m << std::endl;
        if (client_trusted_node_m == nullptr) {
            throw std::runtime_error("Trusted node not found");
        }
        // init beavers triplets and comparision pairs
        beavers_triplets_index_m = 0;
        comparision_pairs_index_m = 0;
        auto cp = get_comparision_pairs(3);
        auto btg = get_beavers_triplets(3);
        for (size_t i = 0; i < btg.size(); i++) {
            delete btg.at(i, 0);
            delete btg.at(i, 1);
            delete btg.at(i, 2);
        }
        for (size_t i = 0; i < cp.size(); i++) {
            delete cp.at(i, 0);
            delete cp.at(i, 1);
        }
        std::cout << "Beavers triplets and comparision pairs initialized"
                  << std::endl;
    }

    void reinit_partial_decryption_clients() {
        clients_cofhe_node_m.clear();
        SetupNodeRequest req = SetupNodeRequest(
            SetupNodeRequest::RequestType::NetworkDetailsRequest,
            NetworkDetailsRequest(NetworkDetailsRequest::RequestType::GET, "")
                .to_string());
        SetupNodeResponse* res;
        client_trusted_node_m->run(Network::ServiceType::SETUP_REQUEST, req,
                                   &res);
        network_details_m = NetworkDetails::from_string(
            NetworkDetailsResponse::from_string(res->data()).data());
        clients_cofhe_node_m.clear();
        std::vector<size_t> partial_decryption_clients;
        size_t i = 0;
        for (const auto& node : network_details_m.nodes()) {
            try {
                if (node.type == NodeType::CoFHE_NODE) {
                    ++i;
                    clients_cofhe_node_m.push_back(
                        std::make_unique<Network::Client>(node.ip, node.port));
                    partial_decryption_clients.push_back(i);
                }
            } catch (const std::exception& e) {
                std::cerr << e.what() << '\n';
            }
            if (clients_cofhe_node_m.size() >=
                network_details_m.cryptosystem_details().threshold) {
                break;
            }
        }
        if (clients_cofhe_node_m.size() <
            network_details_m.cryptosystem_details().threshold) {
            throw std::runtime_error("Not enough partial decryption clients");
        }
        part_decryption_index_m = combinationSequenceNumber(
            network_details_m.cryptosystem_details().total_nodes,
            network_details_m.cryptosystem_details().threshold,
            partial_decryption_clients);
    }

    Vector<PartialDecryptionResult> partial_decrypt(CipherText ct) {
        if (clients_cofhe_node_m.size() <
            network_details_m.cryptosystem_details().threshold) {
            reinit_partial_decryption_clients();
        }
        auto request = CoFHENodeRequest(
            CoFHENodeRequest::RequestType::PartialDecryption,
            PartialDecryptionRequest(part_decryption_index_m,
                                     PartialDecryptionRequest::DataType::SINGLE,
                                     crypto_system_m.serialize_ciphertext(ct))
                .to_string());
        std::vector<CoFHE::CoFHENodeResponse*> res(
            network_details_m.cryptosystem_details().threshold, nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            clients_cofhe_node_m[i]->run(Network::ServiceType::COFHE_REQUEST,
                                         request, &res[i]);
        }
        Vector<PartialDecryptionResult> pdrs;
        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            if (!res[i] ||
                res[i]->header().status() != CoFHENodeResponse::Status::OK) {
                for (size_t j = 0; j < i; j++) {
                    delete res[j];
                }
                throw std::runtime_error("Partial decryption failed");
            }
            pdrs.push_back(
                crypto_system_m.deserialize_partial_decryption_result(
                    PartialDecryptionResponse::from_string((res[i])->data())
                        .data()));
        }
        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            delete res[i];
        }
        return pdrs;
    }

    Vector<Tensor<PartialDecryptionResult*>>
    partial_decrypt_tensor(Tensor<CipherText*> ct) {
        if (clients_cofhe_node_m.size() <
            network_details_m.cryptosystem_details().threshold) {
            reinit_partial_decryption_clients();
        }
        auto request = CoFHENodeRequest(
            CoFHENodeRequest::RequestType::PartialDecryption,
            PartialDecryptionRequest(
                part_decryption_index_m,
                PartialDecryptionRequest::DataType::TENSOR,
                crypto_system_m.serialize_ciphertext_tensor(ct))
                .to_string());
        std::vector<CoFHE::CoFHENodeResponse*> res(
            network_details_m.cryptosystem_details().threshold);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                                i < network_details_m
                                                        .cryptosystem_details()
                                                        .threshold;
                                                i++) {
            clients_cofhe_node_m[i]->run(Network::ServiceType::COFHE_REQUEST,
                                         request, &res[i]);
        }
        Vector<Tensor<PartialDecryptionResult*>> pdrs;
        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            if (!res[i] ||
                res[i]->header().status() != CoFHENodeResponse::Status::OK) {
                for (size_t j = 0; j < i; j++) {
                    delete res[j];
                }
                throw std::runtime_error("Partial decryption failed");
            }
            pdrs.push_back(
                crypto_system_m.deserialize_partial_decryption_result_tensor(
                    PartialDecryptionResponse::from_string((res[i])->data())
                        .data()));
        }

        for (size_t i = 0;
             i < network_details_m.cryptosystem_details().threshold; i++) {
            delete res[i];
        }

        return pdrs;
    }

    int binomialCoefficient(int n, int k) {
        if (k > n)
            return 0;
        if (k == 0 || k == n)
            return 1;

        int result = 1;
        for (int i = 1; i <= k; ++i) {
            result *= (n - i + 1);
            result /= i;
        }
        return result;
    }

    int combinationSequenceNumber(int n, int k,
                                  const std::vector<size_t>& combination) {
        // this does not work
        return 0;
        int rank = 0;
        for (int i = 0; i < k; ++i) {
            int start = (i == 0) ? 1 : combination[i - 1] + 1;
            for (int j = start; j < combination[i]; ++j) {
                rank += binomialCoefficient(n - j, k - i - 1);
            }
        }
        return rank + 1;
    }
};
} // namespace CoFHE

#endif