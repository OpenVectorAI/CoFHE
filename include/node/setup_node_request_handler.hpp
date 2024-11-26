#ifndef COFHE_NODE_SETUP_NODE_REQUEST_HANDLER_HPP_INCLUDED
#define COFHE_NODE_SETUP_NODE_REQUEST_HANDLER_HPP_INCLUDED

#include "node/network_details.hpp"
#include "node/beavers_triplet_request_handler.hpp"
#include "node/join_as_node.hpp"
#include "node/network_details_request_handler.hpp"

namespace CoFHE
{
    class SetupNodeResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        class SetupNodeResponseHeader
        {
        public:
            SetupNodeResponseHeader(Status status, size_t data_size) : status_m(status), data_size_m(data_size) {}

            Status &status() { return status_m; }
            const Status &status() const { return status_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static SetupNodeResponseHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int status;
                size_t data_size;
                iss_line >> status >> data_size;
                return SetupNodeResponseHeader(static_cast<Status>(status), data_size);
            }

        private:
            Status status_m;
            size_t data_size_m;
        };

        SetupNodeResponse(SetupNodeResponseHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        SetupNodeResponse(Status status, std::string data) : header_m(Status::OK, data.size()), data_m(data) {}

        SetupNodeResponseHeader &header() { return header_m; }
        const SetupNodeResponseHeader &header() const { return header_m; }
        Status &status() { return header_m.status(); }
        const Status &status() const { return header_m.status(); }
        size_t &data_size() { return header_m.data_size(); }
        const size_t &data_size() const { return header_m.data_size(); }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return header_m.to_string() + data_m;
        }

        static SetupNodeResponse from_string(std::string str)
        {
            return SetupNodeResponse(SetupNodeResponseHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static SetupNodeResponse from_string(SetupNodeResponseHeader header, std::string str)
        {
            return SetupNodeResponse(header, str);
        }

    private:
        SetupNodeResponseHeader header_m;
        std::string data_m;
    };

    class SetupNodeRequest
    {
    public:
        using ResponseType = SetupNodeResponse;
        enum class RequestType
        {
            BEAVERS_TRIPLET_REQUEST,
            JOIN_AS_NODE_REQUEST,
            NetworkDetailsRequest,
        };

        class SetupNodeRequestHeader
        {
        public:
            SetupNodeRequestHeader(RequestType type, size_t data_size) : type_m(type), data_size_m(data_size) {}

            RequestType &type() { return type_m; }
            const RequestType &type() const { return type_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(type_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static SetupNodeRequestHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int type;
                size_t data_size;
                iss_line >> type >> data_size;
                return SetupNodeRequestHeader(static_cast<RequestType>(type), data_size);
            }

        private:
            RequestType type_m;
            size_t data_size_m;
        };

        SetupNodeRequest(SetupNodeRequestHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        SetupNodeRequest(RequestType type, std::string data) : header_m(type, data.size()), data_m(data) {}

        SetupNodeRequestHeader &header() { return header_m; }
        const SetupNodeRequestHeader &header() const { return header_m; }
        RequestType &type() { return header_m.type(); }
        const RequestType &type() const { return header_m.type(); }
        size_t &data_size() { return header_m.data_size(); }
        const size_t &data_size() const { return header_m.data_size(); }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return header_m.to_string() + data_m;
        }

        static SetupNodeRequest from_string(std::string str)
        {
            return SetupNodeRequest(SetupNodeRequestHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static SetupNodeRequest from_string(SetupNodeRequestHeader header, std::string str)
        {
            return SetupNodeRequest(header, str);
        }

    private:
        SetupNodeRequestHeader header_m;
        std::string data_m;
    };

    template <typename CryptoSystem>
    class SetupNodeRequestHandler
    {
    public:
        using RequestType = SetupNodeRequest;
        using ResponseType = SetupNodeResponse;
        SetupNodeRequestHandler(const NodeDetails &self_details, const CryptoSystemDetails &cryptosystem_details) : join_as_node_handler_m(cryptosystem_details, self_details), beavers_triplet_handler_m(CryptoSystem(cryptosystem_details.security_level, cryptosystem_details.k), join_as_node_handler_m.public_key())
        {
        }

        SetupNodeResponse handle_request(const SetupNodeRequest &req)
        {
            switch (req.type())
            {
            case SetupNodeRequest::RequestType::BEAVERS_TRIPLET_REQUEST:
            {
                return handle_beavers_triplet_request(req);
            }
            case SetupNodeRequest::RequestType::JOIN_AS_NODE_REQUEST:
            {
                return handle_join_as_node_request(req);
            }
            case SetupNodeRequest::RequestType::NetworkDetailsRequest:
            {
                return handle_network_details_request(req);
            }
            default:
                return SetupNodeResponse(SetupNodeResponse::Status::ERROR, "Invalid request type");
            }
        }

    private:
        JoinAsNodeRequestHandler<CryptoSystem> join_as_node_handler_m;
        BeaversTripletRequestHandler<CryptoSystem> beavers_triplet_handler_m;
        NetworkDetailsRequestHandler network_details_handler_m;

        SetupNodeResponse handle_beavers_triplet_request(const SetupNodeRequest &req)
        {
            BeaversTripletRequest beavers_triplet_request = BeaversTripletRequest::from_string(req.data());
            BeaversTripletResponse beavers_triplet_response = beavers_triplet_handler_m.handle_request(beavers_triplet_request);
            return SetupNodeResponse(SetupNodeResponse::Status::OK, beavers_triplet_response.to_string());
        }

        SetupNodeResponse handle_join_as_node_request(const SetupNodeRequest &req)
        {
            JoinAsNodeRequest join_as_node_request = JoinAsNodeRequest::from_string(req.data());
            JoinAsNodeResponse join_as_node_response = join_as_node_handler_m.handle_request(join_as_node_request);
            return SetupNodeResponse(SetupNodeResponse::Status::OK, join_as_node_response.to_string());
        }

        SetupNodeResponse handle_network_details_request(const SetupNodeRequest &req)
        {
            NetworkDetailsRequest network_details_request = NetworkDetailsRequest::from_string(req.data());
            NetworkDetailsResponse network_details_response = network_details_handler_m.handle_request(network_details_request, join_as_node_handler_m.network_details());
            return SetupNodeResponse(SetupNodeResponse::Status::OK, network_details_response.to_string());
        }
    };
} // namespace CoFHE

#endif