#ifndef CoFHE_NODE_REQUEST_RESPONSE_HPP_INCLUDED
#define CoFHE_NODE_REQUEST_RESPONSE_HPP_INCLUDED

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>


namespace CoFHE
{
    namespace Network
    {
        enum class ProtocolVersion
        {
            V1,
        };
        std::string version_to_string(ProtocolVersion ver)
        {
            switch (ver)
            {
            case ProtocolVersion::V1:
                return "V1";
            default:
                return "Unknown";
            }
        }

        // the beavers triplet will be generated in a set of 512, 512*512, 1024, 1024*1024 or bigger as per the requirement and each genration will have a unique id
        // when doing using the beavers triplet, we must use shares of the same id
        // the stock details must include the id and size of the batches of beavers triplet
        enum class ServiceType
        {
            COMPUTE_REQUEST, // made by the client to the compute node
            COFHE_REQUEST,   // made to the cofhe node
            SETUP_REQUEST,   // made to the setup node
            // PARTIAL_DECRYPTION_REQUEST,   // made by the compute node to the cofhe node
            // NETWORK_DETAILS_REQUEST,      // can be made by any node to any other node(not to client node)
            // JOIN_AS_CoFHE_NODE_REQUEST,   // made by the new machine to the setup node
            // JOIN_AS_COMPUTE_NODE_REQUEST, // made by the compute node to the setup node
            // LEAVE_REQUEST,                // made by the cofhe node to the setup node
            // RE_SETUP_REQUEST,             // made by the setup node to the cofhe nodes, in cases like when total number of nodes have been reached or some other network change
            // RANDOM_NUMBER_REQUEST,        // made by the compute node to the cofhe node
            // BEAVERS_TRIPLET_REQUEST,      // made by the compute node to the cofhe node
            // BEAVERS_TRIPLET_REQUEST,               // made by the cofhe node to the setup node when it might need more beavers triplet
            // BEAVERS_TRIPLET_PROVIDE_REQUEST,       // made by the setup node to the cofhe node when it provides without request, in cases like where current beavers triplet is used by other cofhe node
            // BEAVERS_TRIPLET_STOCK_REQUEST,         // made by the compute node to the cofhe node to see if it has any beavers triplet
            // BEAVERS_TRIPLET_STOCK_PROVIDE_REQUEST, // made by the cofhe node to the compute node to provide details about its stock of beavers triplet
            // SMPC_EVALUATION_CAPABILITY_REQUEST, // made by the compute node to the cofhe node to see if it can do smpc evaluation
            // SMPC_EVALUATION_REQUEST,            // made by the compute node to the cofhe node
        };
        std::string service_type_to_string(ServiceType type)
        {
            switch (type)
            {
            case ServiceType::COMPUTE_REQUEST:
                return "COMPUTE_REQUEST";
            case ServiceType::COFHE_REQUEST:
                return "COFHE_REQUEST";
            case ServiceType::SETUP_REQUEST:
                return "SETUP_REQUEST";
            // case ServiceType::PARTIAL_DECRYPTION_REQUEST:
            //     return "PARTIAL_DECRYPTION_REQUEST";
            // case ServiceType::NETWORK_DETAILS_REQUEST:
            //     return "NETWORK_DETAILS_REQUEST";
            // case ServiceType::JOIN_AS_CoFHE_NODE_REQUEST:
            //     return "JOIN_AS_CoFHE_NODE_REQUEST";
            // case ServiceType::JOIN_AS_COMPUTE_NODE_REQUEST:
            //     return "JOIN_AS_COMPUTE_NODE_REQUEST";
            // case ServiceType::LEAVE_REQUEST:
            //     return "LEAVE_REQUEST";
            // case ServiceType::RE_SETUP_REQUEST:
            //     return "RE_SETUP_REQUEST";
            // case ServiceType::BEAVERS_TRIPLET_REQUEST:
            //     return "BEAVERS_TRIPLET_REQUEST";
            // case ServiceType::BEAVERS_TRIPLET_PROVIDE_REQUEST:
            //     return "BEAVERS_TRIPLET_PROVIDE_REQUEST";
            // case ServiceType::BEAVERS_TRIPLET_STOCK_REQUEST:
            //     return "BEAVERS_TRIPLET_STOCK_REQUEST";
            // case ServiceType::BEAVERS_TRIPLET_STOCK_PROVIDE_REQUEST:
            //     return "BEAVERS_TRIPLET_STOCK_PROVIDE_REQUEST";
            // case ServiceType::SMPC_EVALUATION_CAPABILITY_REQUEST:
            //     return "SMPC_EVALUATION_CAPABILITY_REQUEST";
            // case ServiceType::SMPC_EVALUATION_REQUEST:
            //     return "SMPC_EVALUATION_REQUEST";
            default:
                return "Unknown";
            }
        }

        template <typename T>
        concept ResponseType = requires(T t) {
            typename T::Status;
            { t.to_string() }
              -> std::same_as<std::string>;
            { T::from_string(std::declval<std::string>()) }
              -> std::same_as<T>;
        };

        template <typename T>
        concept RequestType = requires(T t) {
            typename T::ResponseType;
            requires ResponseType<typename T::ResponseType>;
            { t.to_string() }
              -> std::same_as<std::string>;
            { T::from_string(std::declval<std::string>()) }
              -> std::same_as<T>;
        };

        class Response
        {
        public:
            enum class Status
            {
                OK,
                ERROR,
            };
            static std::string status_to_string(Status status)
            {
                switch (status)
                {
                case Status::OK:
                    return "OK";
                case Status::ERROR:
                    return "ERROR";
                default:
                    return "Unknown";
                }
            }
            class ResponseHeader
            {
            public:
                ResponseHeader(ProtocolVersion proto_ver, ServiceType type, Status status, size_t data_size) : ver_m(proto_ver), type_m(type), status_m(status), data_size_m(data_size) {}

                ProtocolVersion &protocol_version() { return ver_m; }
                const ProtocolVersion &protocol_version() const { return ver_m; }
                ServiceType &type() { return type_m; }
                const ServiceType &type() const { return type_m; }
                Status &status() { return status_m; }
                const Status &status() const { return status_m; }
                size_t &data_size() { return data_size_m; }
                const size_t &data_size() const { return data_size_m; }

                std::string to_string() const
                {
                    return std::to_string(static_cast<int>(ver_m)) + " " + std::to_string(static_cast<int>(type_m)) + " " + std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_size_m) + "\n";
                }

                void print() const
                {
                    std::cout << "Protocol Version: " << version_to_string(ver_m) << std::endl;
                    std::cout << "ServiceType: " << service_type_to_string(type_m) << std::endl;
                    std::cout << "Status: " << status_to_string(status_m) << std::endl;
                    std::cout << "Data Size: " << data_size_m << std::endl;
                }

                static ResponseHeader from_string(std::string str)
                {
                    // first line contains the protocol version, service type, status and size separated by space
                    std::istringstream iss(str);
                    std::string line;
                    std::getline(iss, line);
                    std::istringstream iss_line(line);
                    int ver, type, status;
                    size_t data_size;
                    iss_line >> ver >> type >> status >> data_size;
                    ProtocolVersion ver_m = static_cast<ProtocolVersion>(ver);
                    ServiceType type_m = static_cast<ServiceType>(type);
                    Status status_m = static_cast<Status>(status);
                    return ResponseHeader(ver_m, type_m, status_m, data_size);
                }

            private:
                ProtocolVersion ver_m;
                ServiceType type_m;
                Status status_m;
                size_t data_size_m;
            };
            Response() : header_m(ProtocolVersion::V1, ServiceType::COMPUTE_REQUEST, Status::OK, 0), data_m("") {}
            Response(ProtocolVersion proto_ver, ServiceType type, Status status, std::string data) : header_m(proto_ver, type, status, data.size()), data_m(data) {}
            Response(ResponseHeader header, std::string data) : header_m(header), data_m(data)
            {
                if (header.data_size() != data.size())
                {
                    throw std::runtime_error("Data size mismatch");
                }
            }

            ResponseHeader &header() { return header_m; }
            const ResponseHeader &header() const { return header_m; }
            ProtocolVersion &protocol_version() { return header_m.protocol_version(); }
            const ProtocolVersion &protocol_version() const { return header_m.protocol_version(); }
            ServiceType &type() { return header_m.type(); }
            const ServiceType &type() const { return header_m.type(); }
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

            void print() const
            {
                header_m.print();
                std::cout << "Data: " << std::hex << data_m << std::endl
                          << std::dec;
            }

            static Response from_string(std::string str)
            {
                // first line contains the protocol version, service type, status and size separated by space
                // the rest of the buffer contains the data
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int ver, type, status, size;
                iss_line >> ver >> type >> status >> size;
                ProtocolVersion ver_m = static_cast<ProtocolVersion>(ver);
                ServiceType type_m = static_cast<ServiceType>(type);
                Status status_m = static_cast<Status>(status);
                auto data = str.substr(line.size() + 1);
                if (data.size() != size)
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return Response(ver_m, type_m, status_m, data);
            }

            static Response from_string(ResponseHeader header, std::string str)
            {
                // str contains the data
                if (header.data_size() != str.size())
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return Response(header, str);
            }

        private:
            ResponseHeader header_m;
            std::string data_m;
        };

        class Request
        {
        public:
            using ResponseType = Response;
            class RequestHeader
            {
            public:
                RequestHeader(ProtocolVersion proto_ver, ServiceType type, size_t data_size) : ver_m(proto_ver), type_m(type), data_size_m(data_size) {}

                ProtocolVersion &protocol_version() { return ver_m; }
                const ProtocolVersion &protocol_version() const { return ver_m; }
                ServiceType &type() { return type_m; }
                const ServiceType &type() const { return type_m; }
                size_t &data_size() { return data_size_m; }
                const size_t &data_size() const { return data_size_m; }

                std::string to_string() const
                {
                    return std::to_string(static_cast<int>(ver_m)) + " " + std::to_string(static_cast<int>(type_m)) + " " + std::to_string(data_size_m) + "\n";
                }

                void print() const
                {
                    std::cout << "Protocol Version: " << version_to_string(ver_m) << std::endl;
                    std::cout << "ServiceType: " << service_type_to_string(type_m) << std::endl;
                    std::cout << "Data Size: " << data_size_m << std::endl;
                }

                static RequestHeader from_string(std::string str)
                {
                    // first line contains the protocol version, service type and size separated by space
                    std::istringstream iss(str);
                    int ver, type, data_size;
                    iss >> ver >> type >> data_size;
                    ProtocolVersion ver_m = static_cast<ProtocolVersion>(ver);
                    ServiceType type_m = static_cast<ServiceType>(type);
                    return RequestHeader(ver_m, type_m, data_size);
                }

            private:
                ProtocolVersion ver_m;
                ServiceType type_m;
                size_t data_size_m;
            };

            Request(ProtocolVersion proto_ver, ServiceType type, std::string data) : header_m(proto_ver, type, data.size()), data_m(data) {}
            Request(RequestHeader header, std::string data) : header_m(header), data_m(data)
            {
                if (header.data_size() != data.size())
                {
                    throw std::runtime_error("Data size mismatch");
                }
            }

            RequestHeader &header() { return header_m; }
            const RequestHeader &header() const { return header_m; }
            ProtocolVersion &protocol_version() { return header_m.protocol_version(); }
            const ProtocolVersion &protocol_version() const { return header_m.protocol_version(); }
            ServiceType &type() { return header_m.type(); }
            const ServiceType &type() const { return header_m.type(); }
            size_t &data_size() { return header_m.data_size(); }
            const size_t &data_size() const { return header_m.data_size(); }
            std::string &data() { return data_m; }
            const std::string &data() const { return data_m; }

            std::string to_string() const
            {
                return header_m.to_string() + data_m;
            }

            void print() const
            {
                header_m.print();
                std::cout << "Data: " << std::hex << data_m << std::endl
                          << std::dec;
            }

            static Request from_string(std::string str)
            {
                // first line contains the protocol version, service type and size separated by space
                // the rest of the buffer contains the data
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int ver, type;
                size_t size;
                iss_line >> ver >> type >> size;
                ProtocolVersion ver_m = static_cast<ProtocolVersion>(ver);
                ServiceType type_m = static_cast<ServiceType>(type);
                auto data = str.substr(line.size() + 1);
                if (data.size() != size)
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return Request(ver_m, type_m, data);
            }

            static Request from_string(RequestHeader header, std::string str)
            {
                // str contains the data
                if (header.data_size() != str.size())
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return Request(header, str);
            }

        private:
            RequestHeader header_m;
            std::string data_m;
        };

    } // namespace Network
} // namespace CoFHE
#endif