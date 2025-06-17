#ifndef CoFHE_BEAVERS_TRIPLET_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_BEAVERS_TRIPLET_REQUEST_HANDLER_HPP_INCLUDED

#include <sstream>
#include <string>
#include <vector>

#include "smpc/beavers_triplet_generation.hpp"

namespace CoFHE {
class BeaversTripletResponse {
  public:
    enum class Status {
        OK,
        ERROR,
    };

    BeaversTripletResponse(Status status, std::string data)
        : status_m(status), data_m(data) {}

    Status& status() { return status_m; }
    const Status& status() const { return status_m; }

    std::string& data() { return data_m; }
    const std::string& data() const { return data_m; }

    std::string to_string() const {
        return std::to_string(static_cast<int>(status_m)) + " " +
               std::to_string(data_m.size()) + "\n" + data_m;
    }

    static BeaversTripletResponse from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string line;
        std::getline(iss, line);
        std::istringstream iss_line(line);
        int status;
        size_t data_size;
        iss_line >> status >> data_size;
        std::string data = str.substr(line.size() + 1);
        if (data.size() != data_size) {
            throw std::runtime_error("Data size mismatch");
        }
        return BeaversTripletResponse(static_cast<Status>(status), data);
    }

  private:
    Status status_m;
    std::string data_m;
};

class BeaversTripletRequest {
  public:
    using ResponseType = BeaversTripletResponse;

    enum class RequestType {
        BEAVERS_TRIPLET_CONVERSION_RANDOMNESS_REQUEST,
        BEAVERS_TRIPLET_AB_PAIR_REQUEST,
        BEAVERS_TRIPLET_CONVERSION_REQUEST,
    };

    BeaversTripletRequest(RequestType type, std::string data)
        : type_m(type), data_m(data) {}
    BeaversTripletRequest(RequestType type, size_t num_triples)
        : type_m(type), data_m(std::to_string(num_triples)) {}

    RequestType& type() { return type_m; }
    const RequestType& type() const { return type_m; }
    std::string& data() { return data_m; }
    const std::string& data() const { return data_m; }
    size_t num_triples() const { return std::stoul(data_m); }

    std::string to_string() const {
        return std::to_string(static_cast<int>(type_m)) + "\n" + data_m;
    }

    static BeaversTripletRequest from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string line;
        std::getline(iss, line);
        std::istringstream iss_line(line);
        int type;
        iss_line >> type;
        std::string data = str.substr(line.size() + 1);
        return BeaversTripletRequest(static_cast<RequestType>(type), data);
    }

  private:
    BeaversTripletRequest::RequestType type_m;
    std::string data_m;
};

template <typename CryptoSystem, typename SHECryptoSystem>
class BeaversTripletRequestHandler {
  public:
    using RequestType = BeaversTripletRequest;
    using ResponseType = BeaversTripletResponse;

    BeaversTripletRequestHandler(
        const CryptoSystem& crypto_system,
        const CryptoSystem::PublicKey& public_key,
        const BeaversTripletGenerationDetails& generation_details)
        : cryptosystem_m(crypto_system), public_key_m(public_key),
          generator_m(crypto_system, public_key, generation_details){}

    BeaversTripletResponse handle_request(const BeaversTripletRequest& req) {
        switch (req.type()) {
        case BeaversTripletRequest::RequestType::
            BEAVERS_TRIPLET_CONVERSION_RANDOMNESS_REQUEST: {
            return handle_randomness_request(req);
        }
        case BeaversTripletRequest::RequestType::
            BEAVERS_TRIPLET_AB_PAIR_REQUEST: {
            return handle_ab_pair_generation_request(req);
        }
        case BeaversTripletRequest::RequestType::
            BEAVERS_TRIPLET_CONVERSION_REQUEST: {
            return handle_conversion_request(req);
        }
        default:
            return BeaversTripletResponse(BeaversTripletResponse::Status::ERROR,
                                          "Invalid request type");
        }
    }

  private:
    CryptoSystem cryptosystem_m;
    CryptoSystem::PublicKey public_key_m;
    BeaversTripletGenerator<CryptoSystem, SHECryptoSystem> generator_m;

    BeaversTripletResponse
    handle_randomness_request(const BeaversTripletRequest& req) {
        return BeaversTripletResponse(
            BeaversTripletResponse::Status::OK,
            generator_m.generate_randomness(req.num_triples()));
    }

    BeaversTripletResponse
    handle_ab_pair_generation_request(const BeaversTripletRequest& req) {
        return BeaversTripletResponse(
            BeaversTripletResponse::Status::OK,
            generator_m.generate_ab_pairs(req.num_triples()));
    }

    BeaversTripletResponse
    handle_conversion_request(const BeaversTripletRequest& req) {
        return BeaversTripletResponse(
            BeaversTripletResponse::Status::OK,
            generator_m.partial_decrypt_she_triplets(
                req.data().substr(req.data().find('\n') + 1),
                req.data().substr(0, req.data().find('\n')) == "lead"));
    }
};
} // namespace CoFHE

#endif