#ifndef COFHE_COFHE_NODE_REQUEST_HANDLER_HPP_INCLUDED
#define COFHE_COFHE_NODE_REQUEST_HANDLER_HPP_INCLUDED

#include <string>
#include <vector>
#include <sstream>

#include "node/network_details.hpp"
#include "node/partial_decryption_request_handler.hpp"

namespace CoFHE
{
    class CoFHENodeResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        class CoFHENodeResponseHeader
        {
        public:
            CoFHENodeResponseHeader(Status status, size_t data_size) : status_m(status), data_size_m(data_size) {}

            Status &status() { return status_m; }
            const Status &status() const { return status_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static CoFHENodeResponseHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int status;
                size_t data_size;
                iss_line >> status >> data_size;
                return CoFHENodeResponseHeader(static_cast<Status>(status), data_size);
            }

        private:
            Status status_m;
            size_t data_size_m;
        };

        CoFHENodeResponse(CoFHENodeResponseHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        CoFHENodeResponse(Status status, std::string data) : header_m(Status::OK, data.size()), data_m(data) {}

        CoFHENodeResponseHeader &header() { return header_m; }
        const CoFHENodeResponseHeader &header() const { return header_m; }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return header_m.to_string() + data_m;
        }

        static CoFHENodeResponse from_string(std::string str)
        {
            return CoFHENodeResponse(CoFHENodeResponseHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static CoFHENodeResponse from_string(CoFHENodeResponseHeader header, std::string str)
        {
            return CoFHENodeResponse(header, str);
        }

    private:
        CoFHENodeResponseHeader header_m;
        std::string data_m;
    };

    class CoFHENodeRequest
    {
    public:
        using ResponseType = CoFHENodeResponse;
        enum class RequestType
        {
            PartialDecryption,
            SMPC,
        };

        class CoFHENodeRequestHeader
        {
        public:
            CoFHENodeRequestHeader(RequestType type, size_t data_size) : type_m(type), data_size_m(data_size) {}

            RequestType &type() { return type_m; }
            const RequestType &type() const { return type_m; }
            size_t &data_size() { return data_size_m; }
            const size_t &data_size() const { return data_size_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(type_m)) + " " + std::to_string(data_size_m) + "\n";
            }

            static CoFHENodeRequestHeader from_string(std::string str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int type;
                size_t data_size;
                iss_line >> type >> data_size;
                return CoFHENodeRequestHeader(static_cast<RequestType>(type), data_size);
            }

        private:
            RequestType type_m;
            size_t data_size_m;
        };

        CoFHENodeRequest(CoFHENodeRequestHeader header, std::string data) : header_m(header), data_m(data)
        {
            if (data.size() != header.data_size())
            {
                throw std::runtime_error("Data size mismatch");
            }
        }

        CoFHENodeRequest(RequestType type, std::string data) : header_m(type, data.size()), data_m(data) {}

        CoFHENodeRequestHeader &header() { return header_m; }
        const CoFHENodeRequestHeader &header() const { return header_m; }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return header_m.to_string() + data_m;
        }

        static CoFHENodeRequest from_string(std::string str)
        {
            return CoFHENodeRequest(CoFHENodeRequestHeader::from_string(str), str.substr(str.find('\n') + 1));
        }

        static CoFHENodeRequest from_string(CoFHENodeRequestHeader header, std::string str)
        {
            return CoFHENodeRequest(header, str);
        }

    private:
        CoFHENodeRequestHeader header_m;
        std::string data_m;
    };

    template <typename CryptoSystem>
    class CoFHENodeRequestHandler
    {
    public:
        using RequestType = CoFHENodeRequest;
        using ResponseType = CoFHENodeResponse;
        using SecretKeyShare = typename CryptoSystem::SecretKeyShare;
        CoFHENodeRequestHandler(const NetworkDetails &nd) : nd_m(nd), cryptosystem_m(nd.cryptosystem_details().security_level, nd.cryptosystem_details().k), pk_m(cryptosystem_m.deserialize_public_key(nd.cryptosystem_details().public_key)), sk_shares_m(), partial_decryption_handler_m(cryptosystem_m, sk_shares_m)
        {
            for (auto &sk_share : nd.secret_key_shares())
            {
                sk_shares_m.push_back(cryptosystem_m.deserialize_secret_key_share(sk_share));
            }
            partial_decryption_handler_m.set_secret_key_shares(sk_shares_m);
        }

        CoFHENodeResponse handle_request(const CoFHENodeRequest &request)
        {
            switch (request.header().type())
            {
            case CoFHENodeRequest::RequestType::PartialDecryption:
            {
                return handle_partial_decryption_request(request);
            }
            case CoFHENodeRequest::RequestType::SMPC:
            {
                return handle_smpc_request(request);
            }
            default:
            {
                return CoFHENodeResponse(CoFHENodeResponse::Status::ERROR, "Invalid request type");
            }
            }
        }

    private:
        NetworkDetails nd_m;
        CryptoSystem cryptosystem_m;
        CryptoSystem::PublicKey pk_m;
        std::vector<SecretKeyShare> sk_shares_m;
        PartialDecryptionRequestHandler<CryptoSystem> partial_decryption_handler_m;

        CoFHENodeResponse handle_partial_decryption_request(const CoFHENodeRequest &request)
        {
            auto partial_decryption_request = PartialDecryptionRequest::from_string(request.data());
            auto partial_decryption_response = partial_decryption_handler_m.handle_request(partial_decryption_request);
            return CoFHENodeResponse(CoFHENodeResponse::Status::OK, partial_decryption_response.to_string());
        }

        CoFHENodeResponse handle_smpc_request(const CoFHENodeRequest &request)
        {
            return CoFHENodeResponse(CoFHENodeResponse::Status::ERROR, "Not implemented");
        }
    };

} // namespace CoFHE

#endif