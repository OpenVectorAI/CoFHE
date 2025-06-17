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

    ComparisionPairGenerator(const CryptoSystemImpl& cs, const PublicKey& pk,
                             const ComparisionPairGenerationDetails& details)
        : cs_m(cs), pk_m(pk),
          min_bound_m(cs.make_plaintext(details.lower_bound())),
          max_bound_m(cs.make_plaintext(details.upper_bound())),
          diff_bound_m(cs.make_plaintext(details.diff_bound())) {}

    Tensor<CipherText*> generate(uint32_t num_pairs) {
        Tensor<PlainText*> pairs(num_pairs, 2, nullptr);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (uint32_t i = 0; i < num_pairs;
                                                i++) {
            auto num1 =
                cs_m.generate_random_plaintext(min_bound_m, max_bound_m);
            auto num2 =
                cs_m.generate_random_plaintext(min_bound_m, max_bound_m);
            auto num2_plus_diff = cs_m.add_plaintexts(num2, diff_bound_m);
            while (cs_m.compare_plaintexts(num1, num2_plus_diff) <= 0) {
                num1 = cs_m.generate_random_plaintext(min_bound_m, max_bound_m);
                num2 = cs_m.generate_random_plaintext(min_bound_m, max_bound_m);
                num2_plus_diff =
                    cs_m.add_plaintexts(num2, diff_bound_m);
            }
            pairs.at(i, 0) = new PlainText(num1);
            pairs.at(i, 1) = new PlainText(num2);
        }
        auto cts = cs_m.encrypt_tensor(pk_m, pairs);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (uint32_t i = 0; i < num_pairs;
                                                i++) {
            delete pairs.at(i, 0);
            delete pairs.at(i, 1);
        }
        return cts;
    }

    Tensor<CipherText*> accumulate(const std::vector<Tensor<CipherText*>>& tensors) {
        auto acc_tensor =
            cs_m.add_ciphertext_tensors(pk_m, tensors[0], tensors[1]);
        for (size_t i = 2; i < tensors.size(); i++) {
            auto new_acc_tensor =
                cs_m.add_ciphertext_tensors(pk_m, acc_tensor, tensors[i]);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t j = 0;
                                                    j < acc_tensor.size();
                                                    j++) {
                delete acc_tensor.at(j, 0);
                delete acc_tensor.at(j, 1);
            }
            acc_tensor = new_acc_tensor;
        }
        return acc_tensor;
    }

  private:
    CryptoSystemImpl cs_m;
    PublicKey pk_m;
    PlainText min_bound_m;
    PlainText max_bound_m;
    PlainText diff_bound_m;
};
} // namespace CoFHE

#endif // COFHE_COMPARATOR_PAIR_GENERATOR_HPP_INCLUDED