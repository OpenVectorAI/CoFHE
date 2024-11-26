#ifndef CoFHE_NETWORK_DETAILS_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_NETWORK_DETAILS_REQUEST_HANDLER_HPP_INCLUDED

#include <string>
#include <sstream>

#include "node/network_details.hpp"

namespace CoFHE
{
    class NetworkDetailsResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        class NetworkDetailsResponseHeader
        {
        public:
            NetworkDetailsResponseHeader(Status status, size_t data_size) : status_m(status), data_size_m(data_size) {}

            Status &status() { return status_m; }
            const Status &status() const { return status_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static NetworkDetailsResponseHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int status;
                size_t data_size;
                iss_line >> status >> data_size;
                return NetworkDetailsResponseHeader(static_cast<Status>(status), data_size);
            }

        private:
            Status status_m;
            size_t data_size_m;
        };

        NetworkDetailsResponse(NetworkDetailsResponseHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        NetworkDetailsResponse(Status status, std::string data) : header_m(Status::OK, data.size()), data_m(data) {}

        NetworkDetailsResponseHeader &header() { return header_m; }
        const NetworkDetailsResponseHeader &header() const { return header_m; }
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

        static NetworkDetailsResponse from_string(std::string str)
        {
            return NetworkDetailsResponse(NetworkDetailsResponseHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static NetworkDetailsResponse from_string(NetworkDetailsResponseHeader header, std::string str)
        {
            return NetworkDetailsResponse(header, str.substr(str.find('\n') + 1));
        }

    private:
        NetworkDetailsResponseHeader header_m;
        std::string data_m;
    };

    class NetworkDetailsRequest
    {
    public:
        using ResponseType = NetworkDetailsResponse;
        enum class RequestType
        {
            GET,
            SET,
        };

        class NetworkDetailsRequestHeader
        {
        public:
            NetworkDetailsRequestHeader(RequestType type, size_t data_size) : type_m(type), data_size_m(data_size) {}

            RequestType &type() { return type_m; }
            const RequestType &type() const { return type_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(type_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static NetworkDetailsRequestHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int type;
                size_t data_size;
                iss_line >> type >> data_size;
                return NetworkDetailsRequestHeader(static_cast<RequestType>(type), data_size);
            }

        private:
            RequestType type_m;
            size_t data_size_m;
        };

        NetworkDetailsRequest(NetworkDetailsRequestHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        NetworkDetailsRequest(RequestType type, std::string data) : header_m(type, data.size()), data_m(data) {}

        NetworkDetailsRequestHeader &header() { return header_m; }
        const NetworkDetailsRequestHeader &header() const { return header_m; }
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

        static NetworkDetailsRequest from_string(std::string str)
        {
            return NetworkDetailsRequest(NetworkDetailsRequestHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static NetworkDetailsRequest from_string(NetworkDetailsRequestHeader header, std::string str)
        {
            return NetworkDetailsRequest(header, str.substr(str.find('\n') + 1));
        }

    private:
        NetworkDetailsRequestHeader header_m;
        std::string data_m;
    };

    class NetworkDetailsRequestHandler
    {
    public:
        using RequestType = NetworkDetailsRequest;
        using ResponseType = NetworkDetailsResponse;
        NetworkDetailsResponse handle_request(const NetworkDetailsRequest &request, NetworkDetails &nd)
        {
            if (request.header().type() == NetworkDetailsRequest::RequestType::GET)
            {
                return handle_get(request, nd);
            }
            else if (request.header().type() == NetworkDetailsRequest::RequestType::SET)
            {
                return handle_set(request, nd);
            }
            else
            {
                return NetworkDetailsResponse(NetworkDetailsResponse::Status::ERROR, "Invalid request type");
            }
        }

    private:
        NetworkDetailsResponse handle_get(const NetworkDetailsRequest &request, const NetworkDetails &nd)
        {
            return NetworkDetailsResponse(NetworkDetailsResponse::Status::OK, nd.to_string());
        }

        NetworkDetailsResponse handle_set(const NetworkDetailsRequest &request, NetworkDetails &nd)
        {
            return NetworkDetailsResponse(NetworkDetailsResponse::Status::OK, "SET Not Implemented");
        }
    };
} // namespace CoFHE
#endif