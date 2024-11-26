#ifndef COFHE_SMPC_CLIENT_HPP_INCLUDED
#define COFHE_SMPC_CLIENT_HPP_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <mutex>

#include "node/network_details.hpp"
#include "node/client.hpp"
#include "node/setup_node_request_handler.hpp"
#include "node/cofhe_node_request_handler.hpp"
#include "node/beavers_triplet_request_handler.hpp"
#include "node/partial_decryption_request_handler.hpp"
#include "node/network_details_request_handler.hpp"

#define CACHE_SIZE  10000 //100000000

namespace CoFHE
{
    template <typename CryptoSystem>
    class SMPCClient
    {
    public:
        using PlainText = typename CryptoSystem::PlainText;
        using CipherText = typename CryptoSystem::CipherText;
        using PartDecryptionResult = typename CryptoSystem::PartDecryptionResult;
        SMPCClient(const NetworkDetails &nd) : network_details_m(nd), crypto_system_m(CryptoSystem(
                                                                          network_details_m.cryptosystem_details().security_level,
                                                                          network_details_m.cryptosystem_details().k)),
                                               public_key_m(crypto_system_m.deserialize_public_key(network_details_m.cryptosystem_details().public_key))
        {
            init();
        }

        SMPCClient(SMPCClient &&other) : network_details_m(other.network_details_m), crypto_system_m(other.crypto_system_m), public_key_m(other.public_key_m)
        {
            std::lock_guard<std::mutex> lock(other.beavers_triplets_mutex_m);
            clients_partial_decryption_m = std::move(other.clients_partial_decryption_m);
            beavers_triplets_m = std::move(other.beavers_triplets_m);
            beavers_triplets_index_m = other.beavers_triplets_index_m;
            client_trusted_node_m = std::move(other.client_trusted_node_m);
        }

        SMPCClient &operator=(SMPCClient &&other)
        {
            if (this != &other)
            {
                network_details_m = other.network_details_m;
                crypto_system_m = other.crypto_system_m;
                public_key_m = other.public_key_m;
                std::lock_guard<std::mutex> lock(other.beavers_triplets_mutex_m);
                clients_partial_decryption_m = std::move(other.clients_partial_decryption_m);
                beavers_triplets_m = std::move(other.beavers_triplets_m);
                beavers_triplets_index_m = other.beavers_triplets_index_m;
                client_trusted_node_m = std::move(other.client_trusted_node_m);
            }
            return *this;
        }

        Tensor<CipherText *> get_beavers_triplets(size_t size)
        {
            if (client_trusted_node_m == nullptr)
            {
                throw std::runtime_error("Trusted node not found");
            }
            std::lock_guard<std::mutex> lock(beavers_triplets_mutex_m);
            if (beavers_triplets_m.size() - beavers_triplets_index_m >= size)
            {
                Tensor<CipherText *> triplets(size, 3);
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = 0; i < size; i++)
                {
                    triplets.at(i, 0) = beavers_triplets_m[beavers_triplets_index_m + i][0];
                    triplets.at(i, 1) = beavers_triplets_m[beavers_triplets_index_m + i][1];
                    triplets.at(i, 2) = beavers_triplets_m[beavers_triplets_index_m + i][2];
                }
                beavers_triplets_index_m += size;
                return triplets;
            }
            else
            {
                auto request = SetupNodeRequest(SetupNodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST, BeaversTripletRequest(size + CACHE_SIZE - (beavers_triplets_m.size() - beavers_triplets_index_m)).to_string());
                SetupNodeResponse *res;
                client_trusted_node_m->run(
                    Network::ServiceType::SETUP_REQUEST,
                    request, &res);
                Tensor<CipherText *> triplets(size, 3);
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = beavers_triplets_index_m; i < beavers_triplets_m.size(); i++)
                {
                    triplets.at(i - beavers_triplets_index_m, 0) = beavers_triplets_m[i][0];
                    triplets.at(i - beavers_triplets_index_m, 1) = beavers_triplets_m[i][1];
                    triplets.at(i - beavers_triplets_index_m, 2) = beavers_triplets_m[i][2];
                }
                size_t curr_req = 0;
                auto res_ = crypto_system_m.deserialize_ciphertext_tensor(BeaversTripletResponse::from_string(res->data()).data());
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = beavers_triplets_m.size() - beavers_triplets_index_m; i < size; i++)
                {
                    triplets.at(i, 0) = res_.at(curr_req, 0);
                    triplets.at(i, 1) = res_.at(curr_req, 1);
                    triplets.at(i, 2) = res_.at(curr_req, 2);
                    curr_req++;
                }
                beavers_triplets_index_m = 0;
                beavers_triplets_m.clear();
                for (size_t i = curr_req; i < res_.size(); i++)
                {
                    beavers_triplets_m.push_back({res_.at(i, 0), res_.at(i, 1), res_.at(i, 2)});
                }
                delete res;
                return triplets;
            }
        };

        PlainText decrypt(CipherText ct)
        {
            if (clients_partial_decryption_m.size() < network_details_m.cryptosystem_details().threshold)
            {
                reinit_partial_decryption_clients();
            }
            // auto request = PartialDecryptionRequest(PartialDecryptionRequest::DataType::SINGLE, crypto_system_m.serialize_ciphertext(ct));
            auto request = CoFHENodeRequest(CoFHENodeRequest::RequestType::PartialDecryption, PartialDecryptionRequest(part_decryption_index_m, PartialDecryptionRequest::DataType::SINGLE, crypto_system_m.serialize_ciphertext(ct)).to_string());
            std::vector<CoFHE::CoFHENodeResponse *> res(network_details_m.cryptosystem_details().threshold, nullptr);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                clients_partial_decryption_m[i]->run(
                    Network::ServiceType::COFHE_REQUEST,
                    request, &res[i]);
            }
            Vector<PartDecryptionResult> pdrs;
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                pdrs.push_back(crypto_system_m.deserialize_part_decryption_result(PartialDecryptionResponse::from_string((res[i])->data()).data()));
            }
            auto res_ = crypto_system_m.combine_part_decryption_results(ct, pdrs);
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                delete res[i];
            }
            return res_;
        }

        Tensor<PlainText *> decrypt_tensor(Tensor<CipherText *> ct)
        {
            if (clients_partial_decryption_m.size() < network_details_m.cryptosystem_details().threshold)
            {
                reinit_partial_decryption_clients();
            }
            auto request = CoFHENodeRequest(CoFHENodeRequest::RequestType::PartialDecryption, PartialDecryptionRequest(part_decryption_index_m, PartialDecryptionRequest::DataType::TENSOR, crypto_system_m.serialize_ciphertext_tensor(ct)).to_string());
            std::vector<CoFHE::CoFHENodeResponse *> res(network_details_m.cryptosystem_details().threshold);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                clients_partial_decryption_m[i]->run(
                    Network::ServiceType::COFHE_REQUEST,
                    request, &res[i]);
            }
            Vector<Tensor<PartDecryptionResult *>> pdrs;
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                pdrs.push_back(crypto_system_m.deserialize_part_decryption_result_tensor(PartialDecryptionResponse::from_string((res[i])->data()).data()));
            }
            auto res_ = crypto_system_m.combine_part_decryption_results_tensor(ct, pdrs);
            for (size_t i = 0; i < network_details_m.cryptosystem_details().threshold; i++)
            {
                delete res[i];
            }
            return res_;
        }

        CryptoSystem &crypto_system() { return crypto_system_m; }
        const CryptoSystem &crypto_system() const { return crypto_system_m; }
        typename CryptoSystem::PublicKey &network_public_key()
        {
            return public_key_m;
        }
        const typename CryptoSystem::PublicKey &network_public_key() const
        {
            return public_key_m;
        }

    private:
        // reinit_partial_decryption_clients might change it
        mutable NetworkDetails network_details_m;
        CryptoSystem crypto_system_m;
        typename CryptoSystem::PublicKey public_key_m;
        std::vector<std::unique_ptr<Network::Client>> clients_partial_decryption_m;
        std::unique_ptr<Network::Client> client_trusted_node_m;
        std::mutex beavers_triplets_mutex_m;
        std::vector<std::array<typename CryptoSystem::CipherText *, 3>> beavers_triplets_m;
        size_t beavers_triplets_index_m = 0;
        size_t part_decryption_index_m = 0;

        void init()
        {
            for (const auto &node : network_details_m.nodes())
            {
                try
                {
                    if (node.type == NodeType::CoFHE_NODE)
                    {
                        if (clients_partial_decryption_m.size() < network_details_m.cryptosystem_details().threshold)
                            clients_partial_decryption_m.push_back(std::make_unique<Network::Client>(node.ip, node.port, true));
                    }
                    else if (node.type == NodeType::SETUP_NODE && client_trusted_node_m == nullptr)
                    {
                        client_trusted_node_m = std::make_unique<Network::Client>(node.ip, node.port, true);
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << e.what() << '\n';
                }
            }
            // init beavers triplets
            auto request = SetupNodeRequest(SetupNodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST, BeaversTripletRequest(CACHE_SIZE).to_string());
            SetupNodeResponse *res;
            client_trusted_node_m->run(
                Network::ServiceType::SETUP_REQUEST,
                request, &res);
            auto res_ = crypto_system_m.deserialize_ciphertext_tensor(BeaversTripletResponse::from_string(res->data()).data());
            for (size_t i = 0; i < res_.size(); i++)
            {
                beavers_triplets_m.push_back({res_.at(i, 0), res_.at(i, 1), res_.at(i, 2)});
            }
            std::cout << "Beavers triplets initialized "<< beavers_triplets_m.size() << std::endl;
            delete res;
        }

        void reinit_partial_decryption_clients()
        {
            clients_partial_decryption_m.clear();
            SetupNodeRequest req = SetupNodeRequest(SetupNodeRequest::RequestType::NetworkDetailsRequest, NetworkDetailsRequest(NetworkDetailsRequest::RequestType::GET, "").to_string());
            SetupNodeResponse *res;
            client_trusted_node_m->run(Network::ServiceType::SETUP_REQUEST, req, &res);
            network_details_m = NetworkDetails::from_string(NetworkDetailsResponse::from_string(res->data()).data());
            clients_partial_decryption_m.clear();
            std::vector<size_t> partial_decryption_clients;
            size_t i = 0;
            for (const auto &node : network_details_m.nodes())
            {
                try
                {
                    if (node.type == NodeType::CoFHE_NODE)
                    {
                        if (clients_partial_decryption_m.size() < network_details_m.cryptosystem_details().threshold)
                        {
                            clients_partial_decryption_m.push_back(std::make_unique<Network::Client>(node.ip, node.port, true));
                            partial_decryption_clients.push_back(++i);
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << e.what() << '\n';
                }
            }
            if (clients_partial_decryption_m.size() < network_details_m.cryptosystem_details().threshold)
            {
                throw std::runtime_error("Not enough partial decryption clients");
            }
            part_decryption_index_m = combinationSequenceNumber(network_details_m.cryptosystem_details().total_nodes, network_details_m.cryptosystem_details().threshold, partial_decryption_clients);
        }

        int binomialCoefficient(int n, int k)
        {
            if (k > n)
                return 0;
            if (k == 0 || k == n)
                return 1;

            int result = 1;
            for (int i = 1; i <= k; ++i)
            {
                result *= (n - i + 1);
                result /= i;
            }
            return result;
        }

        int combinationSequenceNumber(int n, int k, const std::vector<size_t> &combination)
        {
            int rank = 0;
            for (int i = 0; i < k; ++i)
            {
                int start = (i == 0) ? 1 : combination[i - 1] + 1;
                for (int j = start; j < combination[i]; ++j)
                {
                    rank += binomialCoefficient(n - j, k - i - 1);
                }
            }
            return rank + 1;
        }
    };
} // namespace CoFHE

#endif