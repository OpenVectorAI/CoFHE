#ifndef COFHE_REENCRYPTOR_FACTORY_HPP_INCLUDED
#define COFHE_REENCRYPTOR_FACTORY_HPP_INCLUDED

#include "node/network_details.hpp"
#include "smpc/reencryption.hpp"
#include "utils/rsa.hpp"

namespace CoFHE {
template <typename PKCEncryptor>
inline PKCEncryptor make_reencryptor(const ReencryptorDetails& details) {
    if (details.type != ReencryptorType::RSA) {
        throw std::runtime_error("Invalid reencryption type");
    }
    return RSAPKCEncryptor(details.key_size);
}
} // namespace CoFHE

#endif // COFHE_REENCRYPTOR_FACTORY_HPP_INCLUDED