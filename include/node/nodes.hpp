#ifndef COFHE_NODE_NODES_HPP_INCLUDED
#define COFHE_NODE_NODES_HPP_INCLUDED

#include "node/client.hpp"
#include "node/cofhe_node_request_handler.hpp"
#include "node/compute_request_handler.hpp"
#include "node/network_details.hpp"
#include "node/network_details_request_handler.hpp"
#include "node/root_request_handler.hpp"
#include "node/server.hpp"
#include "node/setup_node_request_handler.hpp"
namespace CoFHE {

template <typename CryptoSystem, typename PKCEncryptor,
          typename SHECryptoSystem>
auto make_compute_node(
    const NodeDetails& self_details, const NodeDetails& setup_node,
    const std::string& setup_node_cert_path = "./server.pem",
    const std::string& compute_node_cert_path = "./server.pem",
    const std::string& compute_node_key_path = "./server_key.pem") {
    auto setup_node_client = Network::Client(setup_node.ip, setup_node.port,
                                             setup_node_cert_path, true);
    SetupNodeRequest req = SetupNodeRequest(
        SetupNodeRequest::RequestType::JOIN_AS_NODE_REQUEST,
        JoinAsNodeRequest(JoinAsNodeRequest::RequestType::JOIN_AS_COMPUTE_NODE,
                          self_details.ip, self_details.port)
            .to_string());
    SetupNodeResponse* res;
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR ||
        JoinAsNodeResponse::from_string(res->data()).status() ==
            JoinAsNodeResponse::Status::ERROR) {
        throw std::runtime_error("Error joining as compute node");
    }
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::NetworkDetailsRequest,
        NetworkDetailsRequest(NetworkDetailsRequest::RequestType::GET, "")
            .to_string());
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR ||
        NetworkDetailsResponse::from_string(res->data()).status() ==
            NetworkDetailsResponse::Status::ERROR) {
        throw std::runtime_error("Error getting network details");
    }
    NetworkDetails network_details = NetworkDetails::from_string(
        NetworkDetailsResponse::from_string(res->data()).data());
    network_details.self_node() = self_details;
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::BeaversTripletGenerationDetailsRequest,
        "");
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR)
        throw std::runtime_error("Error getting beavers triplet generation "
                                 "details");
    BeaversTripletGenerationDetails beavers_triplet_details =
        BeaversTripletGenerationDetails::from_string(res->data());
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::ComparisionPairGenerationDetailsRequest,
        "");
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR)
        throw std::runtime_error("Error getting comparision pair generation "
                                 "details");
    ComparisionPairGenerationDetails comparision_pair_details =
        ComparisionPairGenerationDetails::from_string(res->data());
    delete res;

    return Network::Server<
        ComputeRequestHandler<CryptoSystem, PKCEncryptor, SHECryptoSystem>,
        ComputeRequest, ComputeResponse>(
        self_details.ip, self_details.port,
        ComputeRequestHandler<CryptoSystem, PKCEncryptor, SHECryptoSystem>(
            network_details, beavers_triplet_details, comparision_pair_details),
        compute_node_cert_path, compute_node_key_path);
}

template <typename CryptoSystem, typename PKCEncryptor,
          typename SHECryptoSystem>
auto make_cofhe_node(
    const NodeDetails& self_details, const NodeDetails& setup_node,
    const std::string& setup_node_cert_path = "./server.pem",
    const std::string& cofhe_node_cert_path = "./server.pem",
    const std::string& cofhe_node_key_path = "./server_key.pem") {
    auto setup_node_client = Network::Client(setup_node.ip, setup_node.port,
                                             setup_node_cert_path, true);
    SetupNodeRequest req = SetupNodeRequest(
        SetupNodeRequest::RequestType::JOIN_AS_NODE_REQUEST,
        JoinAsNodeRequest(JoinAsNodeRequest::RequestType::JOIN_AS_COFHE_NODE,
                          self_details.ip, self_details.port)
            .to_string());
    SetupNodeResponse* res;
    auto port = setup_node.port;
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR ||
        JoinAsNodeResponse::from_string(res->data()).status() ==
            JoinAsNodeResponse::Status::ERROR) {
        throw std::runtime_error("Error joining as cofhe node");
    }
    auto sk_shares =
        JoinAsNodeResponse::from_string(res->data()).secret_key_shares();
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::NetworkDetailsRequest,
        NetworkDetailsRequest(NetworkDetailsRequest::RequestType::GET, "")
            .to_string());
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR ||
        NetworkDetailsResponse::from_string(res->data()).status() ==
            NetworkDetailsResponse::Status::ERROR) {
        throw std::runtime_error("Error getting network details");
    }
    NetworkDetails network_details = NetworkDetails::from_string(
        NetworkDetailsResponse::from_string(res->data()).data());
    network_details.self_node() = self_details;
    network_details.secret_key_shares() = sk_shares;
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::BeaversTripletGenerationDetailsRequest,
        "CoFHE_NODE");
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR)
        throw std::runtime_error("Error getting beavers triplet generation "
                                 "details");
    BeaversTripletGenerationDetails beavers_triplet_details =
        BeaversTripletGenerationDetails::from_string(res->data());
    delete res;
    req = SetupNodeRequest(
        SetupNodeRequest::RequestType::ComparisionPairGenerationDetailsRequest,
        "");
    setup_node_client.run(Network::ServiceType::SETUP_REQUEST, req, &res);
    if (res->status() == SetupNodeResponse::Status::ERROR)
        throw std::runtime_error("Error getting comparision pair generation "
                                 "details");
    ComparisionPairGenerationDetails comparision_pair_details =
        ComparisionPairGenerationDetails::from_string(res->data());
    delete res;

    return Network::Server<
        CoFHENodeRequestHandler<CryptoSystem, PKCEncryptor, SHECryptoSystem>,
        CoFHENodeRequest, CoFHENodeResponse>(
        self_details.ip, self_details.port,
        CoFHENodeRequestHandler<CryptoSystem, PKCEncryptor, SHECryptoSystem>(
            network_details, beavers_triplet_details, comparision_pair_details),
        cofhe_node_cert_path, cofhe_node_key_path);
}

template <typename CryptoSystem, typename SHECryptoSystem>
auto make_setup_node(
    const NodeDetails& self_details, const CryptoSystemDetails& cs,
    const ReencryptorDetails& reencryptor_details,
    const BeaversTripletGenerationDetails& beavers_triplet_details,
    const ComparisionPairGenerationDetails& comparision_pair_details,
    const std::string& cert_path = "./server.pem",
    const std::string& key_path = "./server_key.pem") {
    return Network::Server<
        SetupNodeRequestHandler<CryptoSystem, SHECryptoSystem>,
        SetupNodeRequest, SetupNodeResponse>(
        self_details.ip, self_details.port,
        SetupNodeRequestHandler<CryptoSystem, SHECryptoSystem>(
            self_details, cs, reencryptor_details, beavers_triplet_details,
            comparision_pair_details),
        cert_path, key_path);
}
} // namespace CoFHE

#endif