#ifndef CoFHE_NETWORK_DETAILS_HPP_INCLUDED
#define CoFHE_NETWORK_DETAILS_HPP_INCLUDED

#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/algorithms.hpp"
#include "common/base64.hpp"

namespace CoFHE {
enum class NodeType { SETUP_NODE, CoFHE_NODE, COMPUTE_NODE, CLIENT_NODE };

inline std::string node_type_to_string(NodeType type) {
    switch (type) {
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

inline NodeType string_to_node_type(const std::string& type) {
    if (type == "SETUP_NODE") {
        return NodeType::SETUP_NODE;
    } else if (type == "CoFHE_NODE") {
        return NodeType::CoFHE_NODE;
    } else if (type == "COMPUTE_NODE") {
        return NodeType::COMPUTE_NODE;
    } else if (type == "CLIENT_NODE") {
        return NodeType::CLIENT_NODE;
    } else {
        throw std::runtime_error("Invalid node type");
    }
}

struct NodeDetails {
    std::string ip;
    std::string port;
    NodeType type;
};

enum class ReencryptorType { RSA };

inline std::string reencryption_type_to_string(ReencryptorType type) {
    switch (type) {
    case ReencryptorType::RSA:
        return "RSA";
    default:
        return "Unknown";
    }
}

inline ReencryptorType string_to_reencryption_type(const std::string& type) {
    if (type == "RSA") {
        return ReencryptorType::RSA;
    } else {
        throw std::runtime_error("Invalid reencryption type");
    }
}

struct ReencryptorDetails {
    // this is not really being used
    // make the factory functions in node codes check this and have some
    // interface or variant return
    ReencryptorType type;
    size_t key_size;
};

enum class CryptoSystemType {
    CoFHE_CPU,
};

inline std::string cryptosystem_type_to_string(CryptoSystemType type) {
    switch (type) {
    case CryptoSystemType::CoFHE_CPU:
        return "CoFHE_CPU";
    default:
        return "Unknown";
    }
}

inline CryptoSystemType string_to_cryptosystem_type(const std::string& type) {
    if (type == "CoFHE_CPU") {
        return CryptoSystemType::CoFHE_CPU;
    } else {
        throw std::runtime_error("Invalid cryptosystem type");
    }
}

struct CryptoSystemDetails {
    // this is not really being used
    // make the factory functions in node codes check this and have some
    // interface or variant return
    CryptoSystemType type;
    std::string public_key;
    size_t security_level;
    size_t k;
    size_t threshold;
    size_t total_nodes;
    std::string N;
};

class NetworkDetails {
  public:
    NetworkDetails() = default;
    NetworkDetails(NodeDetails self_node, std::vector<NodeDetails> nodes,
                   CryptoSystemDetails cryptosystem_details,
                   std::vector<std::string> secret_key_shares,
                   ReencryptorDetails reencryption_details)
        : self_node_m(self_node), nodes_m(nodes),
          cryptosystem_details_m(cryptosystem_details),
          secret_key_shares_m(secret_key_shares),
          reencryption_details_m(reencryption_details) {
        if (self_node_m.type == NodeType::CoFHE_NODE) {
            if (nCr(cryptosystem_details_m.total_nodes,
                    cryptosystem_details_m.threshold) !=
                secret_key_shares_m.size()) {
                throw std::runtime_error("Invalid number of secret key shares");
            }
        }
    }

    NodeDetails& self_node() { return self_node_m; }
    const NodeDetails& self_node() const { return self_node_m; }
    std::vector<NodeDetails>& nodes() { return nodes_m; }
    const std::vector<NodeDetails>& nodes() const { return nodes_m; }
    CryptoSystemDetails& cryptosystem_details() {
        return cryptosystem_details_m;
    }
    const CryptoSystemDetails& cryptosystem_details() const {
        return cryptosystem_details_m;
    }
    std::vector<std::string>& secret_key_shares() {
        return secret_key_shares_m;
    }
    const std::vector<std::string>& secret_key_shares() const {
        return secret_key_shares_m;
    }
    ReencryptorDetails& reencryption_details() {
        return reencryption_details_m;
    }
    const ReencryptorDetails& reencryption_details() const {
        return reencryption_details_m;
    }

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["self_node"]["ip"] = self_node_m.ip;
        j["self_node"]["port"] = self_node_m.port;
        j["self_node"]["type"] = node_type_to_string(self_node_m.type);
        for (const auto& node : nodes_m) {
            j["nodes"].push_back({{"ip", node.ip},
                                  {"port", node.port},
                                  {"type", node_type_to_string(node.type)}});
        }
        j["cryptosystem_details"]["type"] =
            cryptosystem_type_to_string(cryptosystem_details_m.type);
        j["cryptosystem_details"]["public_key"] =
            base64_encode(cryptosystem_details_m.public_key);
        j["cryptosystem_details"]["security_level"] =
            cryptosystem_details_m.security_level;
        j["cryptosystem_details"]["k"] = cryptosystem_details_m.k;
        j["cryptosystem_details"]["threshold"] =
            cryptosystem_details_m.threshold;
        j["cryptosystem_details"]["total_nodes"] =
            cryptosystem_details_m.total_nodes;
        j["cryptosystem_details"]["N"] = cryptosystem_details_m.N;
        j["secret_key_shares"] = nlohmann::json::array();
        for (const auto& share : secret_key_shares_m) {
            j["secret_key_shares"].push_back(base64_encode(share));
        }
        j["reencryption_details"]["type"] =
            reencryption_type_to_string(reencryption_details_m.type);
        j["reencryption_details"]["key_size"] = reencryption_details_m.key_size;
        return j;
    }

    std::string to_string() const { return to_json().dump(); }

    static NetworkDetails from_string(const std::string& json_dump) {
        std::istringstream iss(json_dump);
        nlohmann::json j;
        iss >> j;
        NodeDetails self_node;
        self_node.ip = j["self_node"]["ip"];
        self_node.port = j["self_node"]["port"];
        self_node.type = string_to_node_type(j["self_node"]["type"]);
        std::vector<NodeDetails> nodes;
        for (const auto& node : j["nodes"]) {
            NodeDetails node_details;
            node_details.ip = node["ip"];
            node_details.port = node["port"];
            node_details.type = string_to_node_type(node["type"]);
            nodes.push_back(node_details);
        }
        CryptoSystemDetails cryptosystem_details;
        cryptosystem_details.type =
            string_to_cryptosystem_type(j["cryptosystem_details"]["type"]);
        cryptosystem_details.public_key =
            base64_decode(j["cryptosystem_details"]["public_key"]);
        cryptosystem_details.security_level =
            j["cryptosystem_details"]["security_level"];
        cryptosystem_details.k = j["cryptosystem_details"]["k"];
        cryptosystem_details.threshold = j["cryptosystem_details"]["threshold"];
        cryptosystem_details.total_nodes =
            j["cryptosystem_details"]["total_nodes"];
        cryptosystem_details.N = j["cryptosystem_details"]["N"];
        std::vector<std::string> secret_key_shares;
        for (const auto& share : j["secret_key_shares"]) {
            secret_key_shares.push_back(base64_decode(share));
        }
        ReencryptorDetails reencryption_details;
        reencryption_details.type =
            string_to_reencryption_type(j["reencryption_details"]["type"]);
        reencryption_details.key_size = j["reencryption_details"]["key_size"];
        return NetworkDetails(self_node, nodes, cryptosystem_details,
                              secret_key_shares, reencryption_details);
    }

    static NetworkDetails from_file(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file");
        }
        std::string json_dump;
        std::string line;
        while (std::getline(file, line)) {
            json_dump += line;
        }
        return from_string(json_dump);
    }

  private:
    NodeDetails self_node_m;
    std::vector<NodeDetails> nodes_m;
    CryptoSystemDetails cryptosystem_details_m;
    std::vector<std::string> secret_key_shares_m;
    ReencryptorDetails reencryption_details_m;
};

class BeaversTripletGenerationDetails {
  public:
    BeaversTripletGenerationDetails(const std::string& randomness_lower_bound,
                                    const std::string& randomness_upper_bound,
                                    const std::string& ab_pair_lower_bound,
                                    const std::string& ab_pair_upper_bound,
                                    const std::string& plaintext_modulus,
                                    const std::string& multiplicative_depth,
                                    size_t threshold, size_t total_nodes,
                                    size_t security_level)
        : randomness_lower_bound_m(randomness_lower_bound),
          randomness_upper_bound_m(randomness_upper_bound),
          ab_pair_lower_bound_m(ab_pair_lower_bound),
          ab_pair_upper_bound_m(ab_pair_upper_bound),
          plaintext_modulus_m(plaintext_modulus),
          multiplicative_depth_m(multiplicative_depth), threshold_m(threshold),
          total_nodes_m(total_nodes), security_level_m(security_level) {}

    const std::string& randomness_lower_bound() const {
        return randomness_lower_bound_m;
    }
    const std::string& randomness_upper_bound() const {
        return randomness_upper_bound_m;
    }
    const std::string& ab_pair_lower_bound() const {
        return ab_pair_lower_bound_m;
    }
    const std::string& ab_pair_upper_bound() const {
        return ab_pair_upper_bound_m;
    }
    const std::string& serialized_she_sk_share() const {
        return serialized_she_sk_share_m;
    }
    const std::string& plaintext_modulus() const { return plaintext_modulus_m; }
    const std::string& multiplicative_depth() const {
        return multiplicative_depth_m;
    }
    size_t threshold() const { return threshold_m; }
    size_t total_nodes() const { return total_nodes_m; }
    size_t security_level() const { return security_level_m; }
    const std::string& crypto_context() const { return crypto_context_m; }
    const std::string& serialized_she_public_key() const {
        return serialized_she_public_key_m;
    }

    void set_crypto_context(const std::string& crypto_context) {
        crypto_context_m = crypto_context;
    }
    void set_serialized_she_public_key(
        const std::string& serialized_she_public_key) {
        serialized_she_public_key_m = serialized_she_public_key;
    }
    void
    set_serialized_she_sk_share(const std::string& serialized_she_sk_share) {
        serialized_she_sk_share_m = serialized_she_sk_share;
    }

    std::string to_string() const {
        // first 16 bytes represent start of serialized_she_public_key_m and
        // serialized_she_sk_share_m
        std::string binary_data =
            std::string(2 * 8 + crypto_context_m.size() +
                            serialized_she_public_key_m.size() +
                            serialized_she_sk_share_m.size(),
                        '\0');
        char* data_ptr = binary_data.data();
        uint64_t offset = 16 + crypto_context_m.size();
        std::memcpy(data_ptr, &offset, 8);
        offset += serialized_she_public_key_m.size();
        std::memcpy(data_ptr + 8, &offset, 8);
        std::memcpy(data_ptr + 16, crypto_context_m.data(),
                    crypto_context_m.size());
        std::memcpy(data_ptr + 16 + crypto_context_m.size(),
                    serialized_she_public_key_m.data(),
                    serialized_she_public_key_m.size());
        std::memcpy(data_ptr + 16 + crypto_context_m.size() +
                        serialized_she_public_key_m.size(),
                    serialized_she_sk_share_m.data(),
                    serialized_she_sk_share_m.size());
        return randomness_lower_bound_m + "\n" + randomness_upper_bound_m +
               "\n" + ab_pair_lower_bound_m + "\n" + ab_pair_upper_bound_m +
               "\n" + plaintext_modulus_m + "\n" + multiplicative_depth_m +
               "\n" + std::to_string(threshold_m) + "\n" +
               std::to_string(total_nodes_m) + "\n" +
               std::to_string(security_level_m) + "\n" + binary_data;
    }
    static BeaversTripletGenerationDetails from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string randomness_lower_bound, randomness_upper_bound,
            ab_pair_lower_bound, ab_pair_upper_bound, plaintext_modulus,
            multiplicative_depth, threshold, total_nodes, security_level;
        std::getline(iss, randomness_lower_bound);
        std::getline(iss, randomness_upper_bound);
        std::getline(iss, ab_pair_lower_bound);
        std::getline(iss, ab_pair_upper_bound);
        std::getline(iss, plaintext_modulus);
        std::getline(iss, multiplicative_depth);
        std::getline(iss, threshold);
        std::getline(iss, total_nodes);
        std::getline(iss, security_level);
        std::string binary_data = iss.str().substr(iss.tellg());
        if (binary_data.size() < 16) {
            throw std::runtime_error("Invalid binary data size");
        }
        uint64_t she_public_key_offset, she_sk_share_offset;
        std::memcpy(&she_public_key_offset, binary_data.data(), 8);
        std::memcpy(&she_sk_share_offset, binary_data.data() + 8, 8);
        std::string crypto_context =
            binary_data.substr(16, she_public_key_offset - 16);
        std::string serialized_she_public_key = binary_data.substr(
            she_public_key_offset, she_sk_share_offset - she_public_key_offset);
        std::string serialized_she_sk_share = binary_data.substr(
            she_sk_share_offset, binary_data.size() - she_sk_share_offset);
        auto res = BeaversTripletGenerationDetails(
            randomness_lower_bound, randomness_upper_bound, ab_pair_lower_bound,
            ab_pair_upper_bound, plaintext_modulus, multiplicative_depth,
            std::stoul(threshold), std::stoul(total_nodes),
            std::stoul(security_level));
        res.set_serialized_she_public_key(serialized_she_public_key);
        res.set_serialized_she_sk_share(serialized_she_sk_share);
        res.set_crypto_context(crypto_context);
        return res;
    }

  private:
    std::string randomness_lower_bound_m;
    std::string randomness_upper_bound_m;
    std::string ab_pair_lower_bound_m;
    std::string ab_pair_upper_bound_m;
    std::string plaintext_modulus_m;
    std::string multiplicative_depth_m;
    size_t threshold_m;
    size_t total_nodes_m;
    size_t security_level_m;
    std::string crypto_context_m;
    std::string serialized_she_public_key_m;
    std::string serialized_she_sk_share_m;
};

class ComparisionPairGenerationDetails {
  public:
    ComparisionPairGenerationDetails(const std::string& lower_bound,
                                     const std::string& upper_bound,
                                     const std::string& diff_bound)
        : lower_bound_m(lower_bound), upper_bound_m(upper_bound),
          diff_bound_m(diff_bound) {}

    const std::string& lower_bound() const { return lower_bound_m; }
    const std::string& upper_bound() const { return upper_bound_m; }
    const std::string& diff_bound() const { return diff_bound_m; }

    void set_upper_bound(const std::string& upper_bound) {
        upper_bound_m = upper_bound;
    }

    std::string to_string() const {
        return lower_bound_m + "\n" + upper_bound_m + "\n" + diff_bound_m;
    }
    static ComparisionPairGenerationDetails
    from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string lower_bound, upper_bound, diff_bound;
        std::getline(iss, lower_bound);
        std::getline(iss, upper_bound);
        std::getline(iss, diff_bound);
        return ComparisionPairGenerationDetails(lower_bound, upper_bound,
                                                diff_bound);
    }

  private:
    std::string lower_bound_m;
    std::string upper_bound_m;
    std::string diff_bound_m;
};
} // namespace CoFHE

#endif