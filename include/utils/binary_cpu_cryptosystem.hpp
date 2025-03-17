#ifndef CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED
#define CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED

#include "common/vector.hpp"
#include "node/client_node.hpp"
#include "node/nodes.hpp"
#include "x86_64/cpu_cryptosystem.hpp"

#define NUM_BITS 32

namespace CoFHE {
namespace binary_scheme {
CPUCryptoSystem::CipherText inline encrypt_bit(CPUCryptoSystem& cs,
                                               CPUCryptoSystem::PublicKey& pk,
                                               int bit);

Vector<CPUCryptoSystem::CipherText> inline encrypt_bitwise(
    CPUCryptoSystem& cs, CPUCryptoSystem::PublicKey& pk, unsigned int num);

inline unsigned int decrypt_bit(ClientNode<CPUCryptoSystem>& client_node,
                                const CPUCryptoSystem::CipherText& ct);

inline unsigned int
decrypt_bitwise(ClientNode<CPUCryptoSystem>& client_node,
                const Vector<CPUCryptoSystem::CipherText>& cts);

CPUCryptoSystem::CipherText inline homorphic_and(
    ClientNode<CPUCryptoSystem>& client_node,
    const CPUCryptoSystem::CipherText& ct1,
    const CPUCryptoSystem::CipherText& ct2);

Vector<CPUCryptoSystem::CipherText> inline homorphic_and(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct1,
    const Vector<CPUCryptoSystem::CipherText>& ct2);

CPUCryptoSystem::CipherText inline homorphic_or(
    ClientNode<CPUCryptoSystem>& client_node,
    const CPUCryptoSystem::CipherText& ct1,
    const CPUCryptoSystem::CipherText& ct2);

Vector<CPUCryptoSystem::CipherText> inline homorphic_or(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct1,
    const Vector<CPUCryptoSystem::CipherText>& ct2);

CPUCryptoSystem::CipherText inline homorphic_not(
    ClientNode<CPUCryptoSystem>& client_node,
    const CPUCryptoSystem::CipherText& ct);

Vector<CPUCryptoSystem::CipherText> inline homorphic_not(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct);

CPUCryptoSystem::CipherText inline homorphic_xor(
    ClientNode<CPUCryptoSystem>& client_node,
    const CPUCryptoSystem::CipherText& ct1,
    const CPUCryptoSystem::CipherText& ct2);

Vector<CPUCryptoSystem::CipherText> inline homorphic_xor(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct1,
    const Vector<CPUCryptoSystem::CipherText>& ct2);

Vector<CPUCryptoSystem::CipherText> inline homorphic_add(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct1,
    const Vector<CPUCryptoSystem::CipherText>& ct2);

Vector<CPUCryptoSystem::CipherText> inline homorphic_2s_complement(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct);

Vector<CPUCryptoSystem::CipherText> inline homorphic_sub(
    ClientNode<CPUCryptoSystem>& client_node,
    const Vector<CPUCryptoSystem::CipherText>& ct1,
    const Vector<CPUCryptoSystem::CipherText>& ct2);

CPUCryptoSystem::CipherText inline homorphic_gt(
    ClientNode<CPUCryptoSystem>& client_node,
    Vector<CPUCryptoSystem::CipherText>& ct1,
    Vector<CPUCryptoSystem::CipherText>& ct2);

CPUCryptoSystem::CipherText inline homorphic_lt(
    ClientNode<CPUCryptoSystem>& client_node,
    Vector<CPUCryptoSystem::CipherText>& ct1,
    Vector<CPUCryptoSystem::CipherText>& ct2);

CPUCryptoSystem::CipherText inline homorphic_eq(
    ClientNode<CPUCryptoSystem>& client_node,
    Vector<CPUCryptoSystem::CipherText>& ct1,
    Vector<CPUCryptoSystem::CipherText>& ct2);

#include "utils/binary_cpu_cryptosystem.inl"

} // namespace binary_scheme
} // namespace CoFHE

#endif // CoFHE_BINARY_CPUCRYPTOSYSTEM_HPP_INCLUDED