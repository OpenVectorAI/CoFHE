#ifndef CoFHE_NETWORK_DETAILS_HPP_INCLUDED
#define CoFHE_NETWORK_DETAILS_HPP_INCLUDED

#include <string>
#include <vector>
#include <memory>
#include <fstream>

#include <nlohmann/json.hpp>

#include "common/algorithms.hpp"

#include "cofhe.hpp"

namespace CoFHE
{
    enum class NodeType
    {
        SETUP_NODE,
        CoFHE_NODE,
        COMPUTE_NODE,
        CLIENT_NODE
    };

    std::string node_type_to_string(NodeType type)
    {
        switch (type)
        {
        case NodeType::SETUP_NODE:
            return "SETUP_NODE";
        case NodeType::CoFHE_NODE:
            return "CoFHE_NODE";
        case NodeType::COMPUTE_NODE:
            return "COMPUTE_NODE";
        case NodeType::CLIENT_NODE:
            return "CLIENT_NODE";
        default:
            return "Unknown";
        }
    }

    NodeType string_to_node_type(const std::string &type)
    {
        if (type == "SETUP_NODE")
        {
            return NodeType::SETUP_NODE;
        }
        else if (type == "CoFHE_NODE")
        {
            return NodeType::CoFHE_NODE;
        }
        else if (type == "COMPUTE_NODE")
        {
            return NodeType::COMPUTE_NODE;
        }
        else if (type == "CLIENT_NODE")
        {
            return NodeType::CLIENT_NODE;
        }
        else
        {
            throw std::runtime_error("Invalid node type");
        }
    }

    struct NodeDetails
    {
        std::string ip;
        std::string port;
        NodeType type;
    };

    enum class CryptoSystemType
    {
        CoFHE_CPU,
    };

    std::string cryptosystem_type_to_string(CryptoSystemType type)
    {
        switch (type)
        {
        case CryptoSystemType::CoFHE_CPU:
            return "CoFHE_CPU";
        default:
            return "Unknown";
        }
    }

    CryptoSystemType string_to_cryptosystem_type(const std::string &type)
    {
        if (type == "CoFHE_CPU")
        {
            return CryptoSystemType::CoFHE_CPU;
        }
        else
        {
            throw std::runtime_error("Invalid cryptosystem type");
        }
    }

    struct CryptoSystemDetails
    {
        // this is not really being used
        // make the factory functions in node codes check this and have some interface or variant return
        CryptoSystemType type;
        std::string public_key;
        size_t security_level;
        size_t k;
        size_t threshold;
        size_t total_nodes;
    };

    class NetworkDetails
    {
    public:
        NetworkDetails()=default;
        NetworkDetails(NodeDetails self_node, std::vector<NodeDetails> nodes, CryptoSystemDetails cryptosystem_details, std::vector<std::string> secret_key_shares) : self_node_m(self_node), nodes_m(nodes), cryptosystem_details_m(cryptosystem_details), secret_key_shares_m(secret_key_shares)
        {
            if (self_node_m.type == NodeType::CoFHE_NODE)
            {
                if (nCr(cryptosystem_details_m.total_nodes, cryptosystem_details_m.threshold) != secret_key_shares_m.size())
                {
                    throw std::runtime_error("Invalid number of secret key shares");
                }
            }
        }

        NodeDetails &self_node() { return self_node_m; }
        const NodeDetails &self_node() const { return self_node_m; }
        std::vector<NodeDetails> &nodes() { return nodes_m; }
        const std::vector<NodeDetails> &nodes() const { return nodes_m; }
        CryptoSystemDetails &cryptosystem_details() { return cryptosystem_details_m; }
        const CryptoSystemDetails &cryptosystem_details() const { return cryptosystem_details_m; }
        std::vector<std::string> &secret_key_shares() { return secret_key_shares_m; }
        const std::vector<std::string> &secret_key_shares() const { return secret_key_shares_m; }

        nlohmann::json to_json() const
        {
            nlohmann::json j;
            j["self_node"]["ip"] = self_node_m.ip;
            j["self_node"]["port"] = self_node_m.port;
            j["self_node"]["type"] = node_type_to_string(self_node_m.type);
            for (const auto &node : nodes_m)
            {
                j["nodes"].push_back({{"ip", node.ip}, {"port", node.port}, {"type", node_type_to_string(node.type)}});
            }
            j["cryptosystem_details"]["type"] = cryptosystem_type_to_string(cryptosystem_details_m.type);
            j["cryptosystem_details"]["public_key"] = cryptosystem_details_m.public_key;
            j["cryptosystem_details"]["security_level"] = cryptosystem_details_m.security_level;
            j["cryptosystem_details"]["k"] = cryptosystem_details_m.k;
            j["cryptosystem_details"]["threshold"] = cryptosystem_details_m.threshold;
            j["cryptosystem_details"]["total_nodes"] = cryptosystem_details_m.total_nodes;
            for (const auto &share : secret_key_shares_m)
            {
                j["secret_key_shares"].push_back(share);
            }
            return j;
        }

        std::string to_string() const
        {
            return to_json().dump();
        }

        static NetworkDetails from_string(const std::string &json_dump)
        {
            std::istringstream iss(json_dump);
            nlohmann::json j;
            iss >> j;
            NodeDetails self_node;
            self_node.ip = j["self_node"]["ip"];
            self_node.port = j["self_node"]["port"];
            self_node.type = string_to_node_type(j["self_node"]["type"]);
            std::vector<NodeDetails> nodes;
            for (const auto &node : j["nodes"])
            {
                NodeDetails node_details;
                node_details.ip = node["ip"];
                node_details.port = node["port"];
                node_details.type = string_to_node_type(node["type"]);
                nodes.push_back(node_details);
            }
            CryptoSystemDetails cryptosystem_details;
            cryptosystem_details.type = string_to_cryptosystem_type(j["cryptosystem_details"]["type"]);
            cryptosystem_details.public_key = j["cryptosystem_details"]["public_key"];
            cryptosystem_details.security_level = j["cryptosystem_details"]["security_level"];
            cryptosystem_details.k = j["cryptosystem_details"]["k"];
            cryptosystem_details.threshold = j["cryptosystem_details"]["threshold"];
            cryptosystem_details.total_nodes = j["cryptosystem_details"]["total_nodes"];
            std::vector<std::string> secret_key_shares;
            for (const auto &share : j["secret_key_shares"])
            {
                secret_key_shares.push_back(share);
            }
            return NetworkDetails(self_node, nodes, cryptosystem_details, secret_key_shares);
        }

        static NetworkDetails from_file(const std::string &file_path)
        {
            std::ifstream file(file_path);
            if (!file.is_open())
            {
                throw std::runtime_error("Could not open file");
            }
            std::string json_dump;
            std::string line;
            while (std::getline(file, line))
            {
                json_dump += line;
            }
            return from_string(json_dump);
        }

    private:
        NodeDetails self_node_m;
        std::vector<NodeDetails> nodes_m;
        CryptoSystemDetails cryptosystem_details_m;
        std::vector<std::string> secret_key_shares_m;
    };

} // namespace CoFHE

#endif