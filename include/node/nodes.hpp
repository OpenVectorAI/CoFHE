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

template <typename CryptoSystem>
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
    return Network::Server<ComputeRequestHandler<CryptoSystem>, ComputeRequest,
                           ComputeResponse>(
        self_details.ip, self_details.port,
        ComputeRequestHandler<CryptoSystem>(network_details),
        compute_node_cert_path, compute_node_key_path);
}

template <typename CryptoSystem>
auto make_cofhe_node(const NodeDetails& self_details,
                     const NodeDetails& setup_node,
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
    return Network::Server<CoFHENodeRequestHandler<CryptoSystem>,
                           CoFHENodeRequest, CoFHENodeResponse>(
        self_details.ip, self_details.port,
        CoFHENodeRequestHandler<CryptoSystem>(network_details));
}

template <typename CryptoSystem>
auto make_setup_node(const NodeDetails& self_details,
                     const CryptoSystemDetails& cs,
                     const std::string& cert_path = "./server.pem",
                     const std::string& key_path = "./server_key.pem") {
    return Network::Server<SetupNodeRequestHandler<CryptoSystem>,
                           SetupNodeRequest, SetupNodeResponse>(
        self_details.ip, self_details.port,
        SetupNodeRequestHandler<CryptoSystem>(self_details, cs), cert_path,
        key_path);
}
} // namespace CoFHE

#endif