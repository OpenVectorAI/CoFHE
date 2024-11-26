#ifndef COFHE_NODE_JOIN_AS_NODE_NODE_HPP_INCLUDED
#define COFHE_NODE_JOIN_AS_NODE_NODE_HPP_INCLUDED

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <mutex>

#include "node/network_details.hpp"

namespace CoFHE
{
    class JoinAsNodeResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        enum class ResponseType
        {
            JOIN_AS_COFHE_NODE,
            JOIN_AS_COMPUTE_NODE,
        };

        class JoinAsNodeResponseHeader
        {
        public:
            JoinAsNodeResponseHeader(Status status,
                ResponseType response_type,
             size_t data_size) : status_m(status), response_type_m(response_type), data_size_m(data_size) {}

            Status &status() { return status_m; }
            const Status &status() const { return status_m; }
            ResponseType &response_type() { return response_type_m; }
            const ResponseType &response_type() const { return response_type_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(static_cast<int>(response_type_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static JoinAsNodeResponseHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int status, response_type;
                size_t data_size;
                iss_line >> status >> response_type >> data_size;
                return JoinAsNodeResponseHeader(static_cast<Status>(status), static_cast<ResponseType>(response_type), data_size);
            }

        private:
            Status status_m;
            ResponseType response_type_m;
            size_t data_size_m;
        };

        // for cofhe node
        JoinAsNodeResponse(Status status, std::string public_key, std::vector<std::string> secret_key_shares) : header_m(status, ResponseType::JOIN_AS_COFHE_NODE, public_key.size() + 1), public_key_m(public_key), secret_key_shares_m(secret_key_shares)
        {
            for (const auto &share : secret_key_shares_m)
            {
                header_m.data_size() += share.size() + 1; // 1 for newline
            }
        }

        //for compute node
        JoinAsNodeResponse(Status status): header_m(status, ResponseType::JOIN_AS_COMPUTE_NODE, 0) {}

        // for error
        JoinAsNodeResponse(std::string error_message) : header_m(Status::ERROR, ResponseType::JOIN_AS_COFHE_NODE, error_message.size() + 1), error_message_m(error_message) {}

        JoinAsNodeResponseHeader &header() { return header_m; }
        const JoinAsNodeResponseHeader &header() const { return header_m; }
        Status &status() { return header_m.status(); }
        const Status &status() const { return header_m.status(); }
        ResponseType &response_type() { return header_m.response_type(); }
        const ResponseType &response_type() const { return header_m.response_type(); }
        size_t &data_size() { return header_m.data_size(); }
        const size_t &data_size() const { return header_m.data_size(); }
        std::string &public_key() { return public_key_m; }
        const std::string &public_key() const { return public_key_m; }
        std::vector<std::string> &secret_key_shares() { return secret_key_shares_m; }
        const std::vector<std::string> &secret_key_shares() const { return secret_key_shares_m; }
        std::string &error_message() { return error_message_m; }
        const std::string &error_message() const { return error_message_m; }

        std::string to_string() const
        {
            std::string str = header_m.to_string();
            if (response_type() == ResponseType::JOIN_AS_COFHE_NODE)
            {
                str += public_key_m + "\n";
                for (const auto &share : secret_key_shares_m)
                {
                    str += share + "\n";
                }
            }
            else if (response_type() == ResponseType::JOIN_AS_COMPUTE_NODE)
            {
                // do nothing
            }
            else
            {
                str += error_message_m + "\n";
            }
            return str;
        }

        static JoinAsNodeResponse from_string(const std::string &str)
        {
            std::istringstream iss(str);
            std::string line;
            std::getline(iss, line);
            auto header = JoinAsNodeResponseHeader::from_string(line);
            if (header.response_type() == ResponseType::JOIN_AS_COFHE_NODE)
            {
                std::string public_key;
                std::getline(iss, public_key);
                std::vector<std::string> secret_key_shares;
                while (std::getline(iss, line))
                {
                    secret_key_shares.push_back(line);
                }
                return JoinAsNodeResponse(header.status(), public_key, secret_key_shares);
            }
            else if (header.response_type() == ResponseType::JOIN_AS_COMPUTE_NODE)
            {
                return JoinAsNodeResponse(header.status());
            }
            else
            {
                std::string error_message;
                std::getline(iss, error_message);
                return JoinAsNodeResponse(error_message);
            }
        }

        static JoinAsNodeResponse from_string(JoinAsNodeResponseHeader header, const std::string &str)
        {
            std::istringstream iss(str);
            if (header.response_type() == ResponseType::JOIN_AS_COFHE_NODE)
            {
                std::string public_key;
                std::getline(iss, public_key);
                std::vector<std::string> secret_key_shares;
                std::string line;
                while (std::getline(iss, line))
                {
                    secret_key_shares.push_back(line);
                }
                return JoinAsNodeResponse(header.status(), public_key, secret_key_shares);
            }
            else if (header.response_type() == ResponseType::JOIN_AS_COMPUTE_NODE)
            {
                return JoinAsNodeResponse(header.status());
            }
            else
            {
                std::string error_message;
                std::getline(iss, error_message);
                return JoinAsNodeResponse(error_message);
            }
        }

        private:
            JoinAsNodeResponseHeader header_m;
            std::string public_key_m;
            std::vector<std::string> secret_key_shares_m;
            std::string error_message_m;
    };

    class JoinAsNodeRequest
    {
    public:
        enum class RequestType
        {
            JOIN_AS_COFHE_NODE,
            JOIN_AS_COMPUTE_NODE,
        };
        using ResponseType = JoinAsNodeResponse;
        class JoinAsNodeRequestHeader
        {
        public:
            JoinAsNodeRequestHeader(RequestType type, size_t data_size) : type_m(type), data_size_m(data_size) {}

            RequestType &type() { return type_m; }
            const RequestType &type() const { return type_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(type_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static JoinAsNodeRequestHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int type;
                size_t data_size;
                iss_line >> type >> data_size;
                return JoinAsNodeRequestHeader(static_cast<RequestType>(type), data_size);
            }

        private:
            RequestType type_m;
            size_t data_size_m;
        };

        JoinAsNodeRequest(JoinAsNodeRequestHeader header, std::string ip, std::string port) : header_m(header), ip_m(ip), port_m(port)
        {
            if (header_m.data_size() != ip_m.size() + 1 + port_m.size() + 1)
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        JoinAsNodeRequest(RequestType type, std::string ip, std::string port) : header_m(type, ip.size() + 1 + port.size() + 1), ip_m(ip), port_m(port) {}

        JoinAsNodeRequestHeader &header() { return header_m; }
        const JoinAsNodeRequestHeader &header() const { return header_m; }
        RequestType &type() { return header_m.type(); }
        const RequestType &type() const { return header_m.type(); }
        size_t &data_size() { return header_m.data_size(); }
        const size_t &data_size() const { return header_m.data_size(); }
        std::string &ip() { return ip_m; }
        const std::string &ip() const { return ip_m; }
        std::string &port() { return port_m; }
        const std::string &port() const { return port_m; }

        std::string to_string() const
        {
            return header_m.to_string() + ip_m + " " + port_m;
        }

        static JoinAsNodeRequest from_string(const std::string &str)
        {
            std::istringstream iss(str);
            std::string line;
            std::getline(iss, line);
            auto header = JoinAsNodeRequestHeader::from_string(line);
            std::string ip, port;
            iss >> ip >> port;
            return JoinAsNodeRequest(header, ip, port);
        }

        static JoinAsNodeRequest from_string(JoinAsNodeRequestHeader header, const std::string &str)
        {
            std::istringstream iss(str);
            std::string ip, port;
            iss >> ip >> port;
            return JoinAsNodeRequest(header, ip, port);
        }

    private:
        JoinAsNodeRequestHeader header_m;
        std::string ip_m;
        std::string port_m;
    };

    template <typename CryptoSystem>
    class JoinAsNodeRequestHandler
    {
    public:
        using RequestType = JoinAsNodeRequest;
        using ResponseType = JoinAsNodeResponse;

        JoinAsNodeRequestHandler(const CryptoSystemDetails &cryptosystem_details, const NodeDetails &self_node) : cryptosystem_details_m(cryptosystem_details), self_node_m(self_node), crypto_system_m(cryptosystem_details.security_level, cryptosystem_details.k), threshold_m(cryptosystem_details.threshold), total_nodes_m(cryptosystem_details.total_nodes)
        {
            init();
        }

        JoinAsNodeRequestHandler(JoinAsNodeRequestHandler &&other) : cryptosystem_details_m(other.cryptosystem_details_m), self_node_m(other.self_node_m), crypto_system_m(other.crypto_system_m), threshold_m(other.threshold_m), total_nodes_m(other.total_nodes_m), public_key_p_m(other.public_key_p_m), public_key_m(other.public_key_m), secret_key_shares_m(other.secret_key_shares_m)
        {
            std::lock_guard<std::mutex> lock(other.mtx_m);
            current_node_m = 0;
            network_details_m = other.network_details_m;
            other.public_key_p_m = nullptr;
        }

        JoinAsNodeRequestHandler &operator=(JoinAsNodeRequestHandler &&other)
        {
            if (this != &other)
            {
                cryptosystem_details_m = other.cryptosystem_details_m;
                self_node_m = other.self_node_m;
                crypto_system_m = other.crypto_system_m;
                threshold_m = other.threshold_m;
                total_nodes_m = other.total_nodes_m;
                public_key_p_m = other.public_key_p_m;
                public_key_m = other.public_key_m;
                secret_key_shares_m = other.secret_key_shares_m;
                std::lock_guard<std::mutex> lock(other.mtx_m);
                current_node_m = 0;
                network_details_m = other.network_details_m;
                other.public_key_p_m = nullptr;
            }
            return *this;
        }

        ~JoinAsNodeRequestHandler()
        {
            delete public_key_p_m;
        }

        JoinAsNodeResponse handle_request(JoinAsNodeRequest req)
        {
            if (req.type() == JoinAsNodeRequest::RequestType::JOIN_AS_COFHE_NODE)
            {
                return handle_join_as_cofhe_node(req);
            }
            else if (req.type() == JoinAsNodeRequest::RequestType::JOIN_AS_COMPUTE_NODE)
            {
                return handle_join_as_compute_node(req);
            }
            return JoinAsNodeResponse("Invalid request type");
        }

        NetworkDetails &network_details()
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            return network_details_m;
        }
        const NetworkDetails &network_details() const
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            return network_details_m;
        }
        typename CryptoSystem::PublicKey &public_key()
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            return *public_key_p_m;
        }
        const typename CryptoSystem::PublicKey &public_key() const
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            return *public_key_p_m;
        }

    private:
        CryptoSystemDetails cryptosystem_details_m;
        NodeDetails self_node_m;
        CryptoSystem crypto_system_m;
        int threshold_m;
        int total_nodes_m;
        mutable std::mutex mtx_m;
        typename CryptoSystem::PublicKey *public_key_p_m;
        std::string public_key_m;
        std::vector<std::vector<std::string>> secret_key_shares_m;
        mutable int current_node_m;
        NetworkDetails network_details_m;

        void init()
        {
            network_details_m.self_node() = self_node_m;
            network_details_m.cryptosystem_details() = cryptosystem_details_m;
            network_details_m.nodes().push_back(self_node_m);
            current_node_m = 0;
            auto sk = crypto_system_m.keygen();
            public_key_p_m = new typename CryptoSystem::PublicKey(crypto_system_m.keygen(sk));
            public_key_m = crypto_system_m.serialize_public_key(*public_key_p_m);
            network_details_m.cryptosystem_details().public_key = public_key_m;
            auto sk_shares = crypto_system_m.keygen(sk, threshold_m, total_nodes_m);
            for (const auto &party : sk_shares)
            {
                std::vector<std::string> secret_key_shares_m_party;
                for (const auto &share : party)
                {
                    secret_key_shares_m_party.push_back(crypto_system_m.serialize_secret_key_share(share));
                }
                secret_key_shares_m.push_back(secret_key_shares_m_party);
            }
        }

        JoinAsNodeResponse handle_join_as_cofhe_node(JoinAsNodeRequest req)
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            if (current_node_m >= total_nodes_m)
            {
                // pub key conatins error change this
                return JoinAsNodeResponse("No more nodes can join");
            }
            network_details_m.nodes().push_back(NodeDetails(req.ip(), req.port(), NodeType::CoFHE_NODE));
            auto res = JoinAsNodeResponse(JoinAsNodeResponse::Status::OK, public_key_m, secret_key_shares_m[current_node_m]);
            current_node_m++;
            return res;
        }

        JoinAsNodeResponse handle_join_as_compute_node(JoinAsNodeRequest req)
        {
            std::lock_guard<std::mutex> lock(mtx_m);
            network_details_m.nodes().push_back(NodeDetails(req.ip(), req.port(), NodeType::COMPUTE_NODE));
            return JoinAsNodeResponse(JoinAsNodeResponse::Status::OK);
        }
    };

} // namespace CoFHE

#endif