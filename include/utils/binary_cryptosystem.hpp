#ifndef CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED
#define CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED

#include "common/vector.hpp"
#include "node/client_node.hpp"
#include "node/nodes.hpp"
#include "x86_64/cpu_cryptosystem.hpp"

#define NUM_BITS 32

namespace CoFHE {
namespace binary_scheme {
template <typename CryptoSystem>
typename CryptoSystem::CipherText inline encrypt_bit(
    CryptoSystem& cs, const typename CryptoSystem::PublicKey& pk, int bit);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline encrypt_bitwise(
    CryptoSystem& cs, const typename CryptoSystem::PublicKey& pk,
    unsigned int num);

template <typename CryptoSystem>
inline unsigned int decrypt_bit(ClientNode<CryptoSystem>& client_node,
                                const typename CryptoSystem::CipherText& ct);

template <typename CryptoSystem>
inline unsigned int
decrypt_bitwise(ClientNode<CryptoSystem>& client_node,
                const Vector<typename CryptoSystem::CipherText>& cts);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_and(
    ClientNode<CryptoSystem>& client_node, const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_and(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_or(
    ClientNode<CryptoSystem>& client_node, const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_or(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_not(
    ClientNode<CryptoSystem>& client_node, const typename CryptoSystem::CipherText& ct);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_not(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_xor(
    ClientNode<CryptoSystem>& client_node, const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_xor(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_add(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_2s_complement(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_sub(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_gt(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_lt(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_eq(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2);

template <typename CryptoSystem>
std::string inline serialize_bit(const CryptoSystem& cs,
                                 const typename CryptoSystem::CipherText& ct);

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline deserialize_bit(const CryptoSystem& cs,
                                                const std::string& str);

template <typename CryptoSystem>
std::string inline serialize_bitwise(
    const CryptoSystem& cs, const Vector<typename CryptoSystem::CipherText>& cts);

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline deserialize_bitwise(
    const CryptoSystem& cs, const std::string& str);

#include "utils/binary_cryptosystem.inl"

} // namespace binary_scheme
} // namespace CoFHE

#endif // CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED