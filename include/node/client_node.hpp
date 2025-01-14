#ifndef COFHE_CLIENT_NODE_HPP_INCLUDED
#define COFHE_CLIENT_NODE_HPP_INCLUDED

#include "node/client.hpp"
#include "node/compute_request_handler.hpp"
#include "node/network_details.hpp"

namespace CoFHE {
template <typename CryptoSystem> class ClientNode {
  public:
    ClientNode(const NetworkDetails& network_details,
               const std::string& cert_path = "./server.pem")
        : network_details_m(network_details),
          crypto_system_m(CryptoSystem(
              network_details.cryptosystem_details().security_level,
              network_details.cryptosystem_details().k)),
          network_public_key_m(crypto_system_m.deserialize_public_key(
              network_details.cryptosystem_details().public_key)),
          cert_path_m(cert_path) {
        init();
    }

    void compute(ComputeRequest request, ComputeResponse** response) {
        client_m->run(Network::ServiceType::COMPUTE_REQUEST, request, response);
    }

    CryptoSystem& crypto_system() { return crypto_system_m; }
    const CryptoSystem& crypto_system() const { return crypto_system_m; }
    typename CryptoSystem::PublicKey& network_public_key() {
        return network_public_key_m;
    }
    const typename CryptoSystem::PublicKey& network_public_key() const {
        return network_public_key_m;
    }

  private:
    NetworkDetails network_details_m;
    CryptoSystem crypto_system_m;
    typename CryptoSystem::PublicKey network_public_key_m;
    std::unique_ptr<Network::Client> client_m;
    std::string cert_path_m;

    void init() {
        for (const auto& node : network_details_m.nodes()) {
            try {
                if (node.type == NodeType::COMPUTE_NODE) {
                    client_m = std::make_unique<Network::Client>(
                        node.ip, node.port, cert_path_m, true);
                }
            } catch (const std::exception& e) {
                std::cerr << e.what() << '\n';
            }
            if (client_m != nullptr)
                break;
        }
    }
};

template <typename CryptoSystem>
auto make_client_node(const NodeDetails& setup_node,
                      const std::string& cert_path = "./server.pem") {
    auto setup_node_client =
        Network::Client(setup_node.ip, setup_node.port, cert_path, true);
    SetupNodeRequest req = SetupNodeRequest(
        SetupNodeRequest::RequestType::NetworkDetailsRequest,
        NetworkDetailsRequest(NetworkDetailsRequest::RequestType::GET, "")
            .to_string());
    SetupNodeResponse* res;
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    NetworkDetails network_details = NetworkDetails::from_string(
        NetworkDetailsResponse::from_string(res->data()).data());
    delete res;
    return ClientNode<CryptoSystem>(network_details);
}
} // namespace CoFHE

#endif