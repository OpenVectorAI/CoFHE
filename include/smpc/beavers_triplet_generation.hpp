#ifndef COFHE_BEAVERS_TRIPLET_GENERATION_HPP_INCLUDED
#define COFHE_BEAVERS_TRIPLET_GENERATION_HPP_INCLUDED

#include "common/tensor.hpp"

namespace CoFHE {

template <typename CryptoSystem> class BeaversTripletGenerator {
  public:
    using CipherText = typename CryptoSystem::CipherText;
    using PlainText = typename CryptoSystem::PlainText;
    BeaversTripletGenerator(const CryptoSystem& cs,
                            const typename CryptoSystem::PublicKey& pk)
        : cs_m(cs), pk_m(pk) {}

    Tensor<CipherText*> generate(size_t size) {
        Tensor<PlainText*> triplets(size, 3);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            auto min_bound = cs_m.make_plaintext(10);
            auto max_bound = cs_m.make_plaintext(100);
            triplets.at(i, 0) =
                new PlainText(cs_m.generate_random_plaintext(min_bound,max_bound));
            triplets.at(i, 1) =
                new PlainText(cs_m.generate_random_plaintext(min_bound,max_bound));
            triplets.at(i, 2) = new PlainText(cs_m.multiply_plaintexts(
                *triplets.at(i, 0), *triplets.at(i, 1)));
        }
        auto enc = cs_m.encrypt_tensor(pk_m, triplets);
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < size; i++) {
            delete triplets.at(i, 0);
            delete triplets.at(i, 1);
            delete triplets.at(i, 2);
        }
        return enc;
    }

  private:
    CryptoSystem cs_m;
    CryptoSystem::PublicKey pk_m;
};
} // namespace CoFHE
#endif