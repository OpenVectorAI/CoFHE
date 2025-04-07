#ifndef COFHE_COMPARATOR_PAIR_GENERATOR_HPP_INCLUDED
#define COFHE_COMPARATOR_PAIR_GENERATOR_HPP_INCLUDED

#include "common/macros.hpp"
#include "common/tensor.hpp"

namespace CoFHE {
template <typename CryptoSystemImpl> class ComparisionPairGenerator {
  public:
    using CipherText = typename CryptoSystemImpl::CipherText;
    using PlainText = typename CryptoSystemImpl::PlainText;
    using PublicKey = typename CryptoSystemImpl::PublicKey;
    using SecretKey = typename CryptoSystemImpl::SecretKey;
    using SecretKeyShare = typename CryptoSystemImpl::SecretKeyShare;
    using PartialDecryptionResult =
        typename CryptoSystemImpl::PartialDecryptionResult;

    ComparisionPairGenerator(const CryptoSystemImpl& cs, const PublicKey& pk)
        : cs_m(cs), pk_m(pk) {}

    Tensor<CipherText*> generate(uint32_t num_pairs) {
        Tensor<PlainText*> pairs(num_pairs, 2, nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (uint32_t i = 0; i < num_pairs; i++) {
            uint64_t num1 = (std::rand()) % 100+10;
            uint64_t num2 = (std::rand()) % 100+10;
            num1 += num2 + 5;
            pairs.at(i, 0) = new PlainText(cs_m.make_plaintext(num1));
            pairs.at(i, 1) = new PlainText(cs_m.make_plaintext(num2));
        }
        auto cts = cs_m.encrypt_tensor(pk_m, pairs);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
        for (uint32_t i = 0; i < num_pairs; i++) {
            delete pairs.at(i, 0);
            delete pairs.at(i, 1);
        }
        return cts;
    }

  private:
    CryptoSystemImpl cs_m;
    PublicKey pk_m;
};
} // namespace CoFHE

#endif // COFHE_COMPARATOR_PAIR_GENERATOR_HPP_INCLUDED