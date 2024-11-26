#ifndef CoFHE_HPP_INCLUDED
#define CoFHE_HPP_INCLUDED

#include <cstdint>

#include "common/pimpl.hpp"
#include "common/vector.hpp"
#include "common/tensor.hpp"
#include "common/pointers.hpp"
#include "x86_64/cpu_cryptosystem.hpp"

namespace CoFHE
{

  template <typename T1, typename T2>
  using Pair = std::pair<T1, T2>;

  template <typename CryptoSystemImpl, typename SecretKeyImpl, typename PublicKeyImpl, typename PlainTextImpl, typename CipherTextImpl, typename SecretKeyShareImpl, typename PartDecryptionResult>
  concept CryptoSystemConcept = requires(CryptoSystemImpl cs, SecretKeyImpl sk, PublicKeyImpl pk, PlainTextImpl pt, CipherTextImpl ct, SecretKeyShareImpl sks, PartDecryptionResult pdr) {
    { cs.keygen() } -> std::same_as<SecretKeyImpl>;
    { cs.keygen(sk) } -> std::same_as<PublicKeyImpl>;
    // in sorted order per party
    { cs.keygen(sk, 2, 4) } -> std::same_as<Vector<Vector<SecretKeyShareImpl>>>;
    { cs.encrypt(pk, pt) } -> std::same_as<CipherTextImpl>;
    {cs.encrypt(pk, Vector<PlainTextImpl>{})} -> std::same_as<Vector<CipherTextImpl>>;
    {cs.encrypt_tensor(pk, Tensor<PlainTextImpl>{})} -> std::same_as<Tensor<CipherTextImpl>>;
    { cs.decrypt(sk, ct) } -> std::same_as<PlainTextImpl>;
    {cs.decrypt_vector(sk, Vector<CipherTextImpl>{})} -> std::same_as<Vector<PlainTextImpl>>;
    {cs.decrypt_tensor(sk, Tensor<CipherTextImpl>{})} -> std::same_as<Tensor<PlainTextImpl>>;
    { cs.part_decrypt(SecretKeyShareImpl{}, ct) } -> std::same_as<PartDecryptionResult>;
    {cs.part_decrypt_vector(SecretKeyShareImpl{}, Vector<CipherTextImpl>{})} -> std::same_as<Vector<PartDecryptionResult>>;
    {cs.part_decrypt_tensor(SecretKeyShareImpl{}, Tensor<CipherTextImpl>{})} -> std::same_as<Tensor<PartDecryptionResult>>;
    { cs.combine_part_decryption_results(ct, Vector<PartDecryptionResult>{}) } -> std::same_as<PlainTextImpl>;
    {cs.combine_part_decryption_results_vector(ct, Vector<PartDecryptionResult>{})} -> std::same_as<Vector<PlainTextImpl>>;
    {cs.combine_part_decryption_results_tensor(ct, Vector<Tensor<PartDecryptionResult>>{})} -> std::same_as<Tensor<PlainTextImpl>>;
    { cs.add_ciphertexts(pk, ct, ct) } -> std::same_as<CipherTextImpl>;
    { cs.scal_ciphertext(pk, pt, ct) } -> std::same_as<CipherTextImpl>;
    { cs.add_ciphertext_vectors(pk, Vector<CipherTextImpl>{}, Vector<CipherTextImpl>{}) } -> std::same_as<Vector<CipherTextImpl>>;
    { cs.scal_ciphertext_vector(pk, pt, Vector<CipherTextImpl>{}) } -> std::same_as<Vector<CipherTextImpl>>;
    { cs.scal_ciphertext_vector(pk, Vector<PlainTextImpl>{}, Vector<CipherTextImpl>{}) } -> std::same_as<Vector<CipherTextImpl>>;
    { cs.add_ciphertext_tensors(pk, Tensor<CipherTextImpl>{}, Tensor<CipherTextImpl>{}) } -> std::same_as<Tensor<CipherTextImpl>>;
    {cs.scal_ciphertext_tensors(pk, Tensor<PlainTextImpl>{}, Tensor<CipherTextImpl>{})} -> std::same_as<Tensor<CipherTextImpl>>;
    { cs.generate_random_plaintext() } -> std::same_as<PlainTextImpl>;
    {cs.generate_random_beavers_triplet()} -> std::same_as<Vector<PlainTextImpl>>;
    {cs.add_plaintexts(pt, pt)} -> std::same_as<PlainTextImpl>;
    { cs.multiply_plaintexts(pt, pt) } -> std::same_as<PlainTextImpl>;
    {cs.add_plaintext_tensors(Tensor<PlainTextImpl>{}, Tensor<PlainTextImpl>{})} -> std::same_as<Tensor<PlainTextImpl>>;
    {cs.multiply_plaintext_tensors(Tensor<PlainTextImpl>{}, Tensor<PlainTextImpl>{})} -> std::same_as<Tensor<PlainTextImpl>>;
    {cs.negate_plaintext(pt)} -> std::same_as<PlainTextImpl>;
    {cs.negate_plain_tensor(Tensor<PlainTextImpl>{})} -> std::same_as<Tensor<PlainTextImpl>>;
    {cs.negate_ciphertext(pk, ct)} -> std::same_as<CipherTextImpl>;
    {cs.negate_ciphertext_tensor(pk, Tensor<CipherTextImpl>{})} -> std::same_as<Tensor<CipherTextImpl>>;
    { cs.make_plaintext(0.0f) } -> std::same_as<PlainTextImpl>;
    {cs.get_float_from_plaintext(pt)} -> std::same_as<float>;
    { cs.serialize() } -> std::same_as<String>;
    { cs.serialize_secret_key(sk) } -> std::same_as<String>;
    { cs.serialize_secret_key_share(sks) } -> std::same_as<String>;
    { cs.serialize_public_key(pk) } -> std::same_as<String>;
    { cs.serialize_plaintext(pt) } -> std::same_as<String>;
    { cs.serialize_ciphertext(ct) } -> std::same_as<String>;
    { cs.serialize_part_decryption_result(PartDecryptionResult{}) } -> std::same_as<String>;
    { cs.serialize_plaintext_tensor(Tensor<PlainTextImpl>{}) } -> std::same_as<String>;
    { cs.serialize_ciphertext_tensor(Tensor<CipherTextImpl>{}) } -> std::same_as<String>;
    { cs.serialize_part_decryption_result_tensor(Tensor<PartDecryptionResult>{}) } -> std::same_as<String>;
    { CryptoSystemImpl::deserialize(String{}) } -> std::same_as<CryptoSystemImpl>;
    { cs.deserialize_secret_key(String{}) } -> std::same_as<SecretKeyImpl>;
    { cs.deserialize_secret_key_share(String{}) } -> std::same_as<SecretKeyShareImpl>;
    { cs.deserialize_public_key(String{}) } -> std::same_as<PublicKeyImpl>;
    { cs.deserialize_plaintext(String{}) } -> std::same_as<PlainTextImpl>;
    { cs.deserialize_ciphertext(String{}) } -> std::same_as<CipherTextImpl>;
    { cs.deserialize_part_decryption_result(String{}) } -> std::same_as<PartDecryptionResult>;
    { cs.deserialize_plaintext_tensor(String{}) } -> std::same_as<Tensor<PlainTextImpl>>;
    { cs.deserialize_ciphertext_tensor(String{}) } -> std::same_as<Tensor<CipherTextImpl>>;
    { cs.deserialize_part_decryption_result_tensor(String{}) } -> std::same_as<Tensor<PartDecryptionResult>>;
  };

  enum class Device
  {
    CPU,
    GPU
  };

  enum class Precision
  {
    FP32,
    FP64
  };

  enum class SecurityLevel
  {
    LOW,
    MEDIUM,
    HIGH
  };

  auto make_cryptosystem(uint32_t security_level, std::uint32_t k, __attribute__((unused)) Device device)
  {
    return CPUCryptoSystem{security_level, k};
  }

  auto make_cryptosystem(SecurityLevel security_level, uint32_t k, __attribute__((unused)) Device device)
  {
    uint32_t sec_level = security_level == SecurityLevel::LOW ? 80 : security_level == SecurityLevel::MEDIUM ? 128
                                                                                                             : 256;
    return CPUCryptoSystem{sec_level, k};
  }
  auto make_cryptosystem(SecurityLevel security_level, Precision precision, uint32_t depth, __attribute__((unused)) Device device)
  {
    uint32_t sec_level = security_level == SecurityLevel::LOW ? 80 : security_level == SecurityLevel::MEDIUM ? 128
                                                                                                             : 256;
    uint32_t k = depth;
    if (precision == Precision::FP32)
    {
      k *= 64;
    }
    else
    {
      k *= 128;
    }
    return CPUCryptoSystem{sec_level, depth};
  }

} // namespace CoFHE

#endif