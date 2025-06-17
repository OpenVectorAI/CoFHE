#ifndef CoFHE_COMPARISION_PAIR_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_COMPARISION_PAIR_REQUEST_HANDLER_HPP_INCLUDED

#include <sstream>
#include <string>
#include <vector>

#include "common/macros.hpp"
#include "smpc/comparision_pair_generator.hpp"

namespace CoFHE {
class ComparisionPairResponse {
  public:
    enum class Status { SUCCESS, FAILURE };

    ComparisionPairResponse(Status status, const std::string& data)
        : status_m(status), data_m(data) {}
    ComparisionPairResponse(Status status, std::string&& data)
        : status_m(status), data_m(std::move(data)) {}
    Status status() const { return status_m; }
    const std::string& data() const { return data_m; }

    std::string to_string() const {
        std::ostringstream oss;
        oss << std::to_string(static_cast<int>(status_m)) << " "
            << std::to_string(data_m.size()) << "\n"
            << data_m;
        return oss.str();
    }
    static ComparisionPairResponse from_string(const std::string& str) {
        std::istringstream iss(str);
        std::string line;
        std::getline(iss, line);
        std::istringstream line_iss(line);
        int status_int;
        size_t data_size;
        line_iss >> status_int >> data_size;
        std::string data = str.substr(line.size() + 1);
        if (data.size() != data_size) {
            throw std::runtime_error("Data size mismatch");
        }
        return ComparisionPairResponse(static_cast<Status>(status_int),
                                       std::move(data));
    }

  private:
    Status status_m;
    std::string data_m;
};

class ComparisionPairRequest {
  public:
    using ResponseType = ComparisionPairResponse;
    ComparisionPairRequest(uint32_t num_pairs) : num_pairs_m(num_pairs) {}
    uint32_t num_pairs() const { return num_pairs_m; }

    std::string to_string() const { return std::to_string(num_pairs_m); }

    static ComparisionPairRequest from_string(const std::string& str) {
        std::istringstream iss(str);
        uint32_t num_pairs;
        iss >> num_pairs;
        return ComparisionPairRequest(num_pairs);
    }

  private:
    uint32_t num_pairs_m;
};

template <typename CryptoSystem> class ComparisionPairRequestHandler {
  public:
    using RequestType = ComparisionPairRequest;
    using ResponseType = ComparisionPairResponse;
    using GeneratorType = ComparisionPairGenerator<CryptoSystem>;
    using PublicKey = typename CryptoSystem::PublicKey;
    ComparisionPairRequestHandler(
        const CryptoSystem& crypto_system, const PublicKey& public_key,
        const ComparisionPairGenerationDetails& generation_details)
        : cryptosystem_m(crypto_system), public_key_m(public_key),
          generator_m(crypto_system, public_key, generation_details) {}

    ResponseType handle_request(const RequestType& request) {
        auto res = generator_m.generate(request.num_pairs());
        auto ser_res = cryptosystem_m.serialize_ciphertext_tensor(res);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < res.size();
                                                i++) {
            delete res.at(i, 0);
            delete res.at(i, 1);
        }
        return ResponseType(ResponseType::Status::SUCCESS, std::move(ser_res));
    }

  private:
    CryptoSystem cryptosystem_m;
    PublicKey public_key_m;
    GeneratorType generator_m;
};
} // namespace CoFHE

#endif // CoFHE_COMPARISION_PAIR_REQUEST_HANDLER_HPP_INCLUDED