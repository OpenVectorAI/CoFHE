#ifndef CoFHE_BEAVERS_TRIPLET_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_BEAVERS_TRIPLET_REQUEST_HANDLER_HPP_INCLUDED

#include <string>
#include <vector>
#include <sstream>

#include "smpc/beavers_triplet_generation.hpp"

namespace CoFHE
{
    class BeaversTripletResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        BeaversTripletResponse(Status status, std::string data) : status_m(status), data_m(data) {}

        Status &status() { return status_m; }
        const Status &status() const { return status_m; }

        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_m.size()) + "\n" + data_m;
        }

        static BeaversTripletResponse from_string(const std::string &str)
        {
            std::istringstream iss(str);
            std::string line;
            std::getline(iss, line);
            std::istringstream iss_line(line);
            int status;
            size_t data_size;
            iss_line >> status >> data_size;
            std::string data = str.substr(line.size() + 1);
            if (data.size() != data_size)
            {
                throw std::runtime_error("Data size mismatch");
            }
            return BeaversTripletResponse(static_cast<Status>(status), data);
        }

    private:
        Status status_m;
        std::string data_m;
    };
    class BeaversTripletRequest
    {
    public:
        using ResponseType = BeaversTripletResponse;
        BeaversTripletRequest(size_t num_triples) : num_triples_m(num_triples) {}

        size_t &num_triples() { return num_triples_m; }
        const size_t &num_triples() const { return num_triples_m; }

        std::string to_string() const
        {
            return std::to_string(num_triples_m);
        }

        static BeaversTripletRequest from_string(const std::string &str)
        {
            std::istringstream iss(str);
            size_t num_triples;
            iss >> num_triples;
            return BeaversTripletRequest(num_triples);
        }

    private:
        size_t num_triples_m;
    };

    

    template <typename CryptoSystem>
    class BeaversTripletRequestHandler
    {
    public:
        using RequestType = BeaversTripletRequest;
        using ResponseType = BeaversTripletResponse;

        BeaversTripletRequestHandler(const CryptoSystem &crypto_system, const CryptoSystem::PublicKey &public_key) :
        crypto_system_m(crypto_system), public_key_m(public_key), generator_m(crypto_system, public_key) {}

        BeaversTripletResponse handle_request(const BeaversTripletRequest &req)
        {
            auto triplets = generator_m.generate(req.num_triples());
            auto data = crypto_system_m.serialize_ciphertext_tensor(triplets);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < triplets.size(); i++)
            {
                delete triplets.at(i, 0);
                delete triplets.at(i, 1);
                delete triplets.at(i, 2);
            }
            return BeaversTripletResponse(BeaversTripletResponse::Status::OK, data);
        }
    private:
        CryptoSystem crypto_system_m;
        CryptoSystem::PublicKey public_key_m;
        BeaversTripletGenerator<CryptoSystem> generator_m;
    };
} // namespace CoFHE

#endif