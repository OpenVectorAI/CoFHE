#include "common/tensor.hpp"
#include "node/compute_request_response.hpp"

inline int get_nth_bit(int num, int n) { return (num >> n) & 1; }

inline int get_n_from_bits(Vector<int> bits) {
    int num = 0;
    for (int i = 0; i < bits.size(); i++) {
        num |= bits[i] << i;
    }
    return num;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline encrypt_bit(
    CryptoSystem& cs, const typename CryptoSystem::PublicKey& pk, int bit) {
    return cs.encrypt(pk, cs.make_plaintext(bit));
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline encrypt_bitwise(
    CryptoSystem& cs, const typename CryptoSystem::PublicKey& pk,
    unsigned int num) {
    Vector<typename CryptoSystem::CipherText> cts;
    Tensor<typename CryptoSystem::PlainText*> pt(NUM_BITS, nullptr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (int i = 0; i < NUM_BITS; i++) {
        pt.at(i) =
            new CryptoSystem::PlainText(cs.make_plaintext(get_nth_bit(num, i)));
    }
    auto ct_tensor = cs.encrypt_tensor(pk, pt);
    for (int i = 0; i < NUM_BITS; i++) {
        cts.push_back(*ct_tensor.at(i));
        delete pt.at(i);
    }
    return cts;
}

template <typename CryptoSystem>
inline unsigned int decrypt_bit(ClientNode<CryptoSystem>& client_node,
                                const typename CryptoSystem::CipherText& ct) {
    auto serialized_ct = client_node.crypto_system().serialize_ciphertext(ct);

    ComputeRequest::ComputeOperationOperand decrypt_operand(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct);

    ComputeRequest::ComputeOperationInstance decrypt_operation(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT, {decrypt_operand});

    ComputeRequest req_d(decrypt_operation);
    ComputeResponse* res;

    client_node.compute(req_d, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Decryption failed.");
    }

    auto pt = client_node.crypto_system().deserialize_plaintext(res->data());
    delete res;

    return static_cast<unsigned int>(
        client_node.crypto_system().get_float_from_plaintext(pt));
}

template <typename CryptoSystem>
inline unsigned int
decrypt_bitwise(ClientNode<CryptoSystem>& client_node,
                const Vector<typename CryptoSystem::CipherText>& cts) {
    Tensor<typename CryptoSystem::CipherText*> ct(NUM_BITS, nullptr);
    for (int i = 0; i < NUM_BITS; i++) {
        ct.at(i) = new typename CryptoSystem::CipherText(cts[i]);
    }

    auto serialized_ct =
        client_node.crypto_system().serialize_ciphertext_tensor(ct);

    ComputeRequest::ComputeOperationOperand decrypt_operand(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct);

    ComputeRequest::ComputeOperationInstance decrypt_operation(
        ComputeRequest::ComputeOperationType::UNARY,
        ComputeRequest::ComputeOperation::DECRYPT, {decrypt_operand});

    ComputeRequest req_d(decrypt_operation);
    ComputeResponse* res;

    client_node.compute(req_d, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Decryption failed.");
    }

    auto pt =
        client_node.crypto_system().deserialize_plaintext_tensor(res->data());
    delete res;

    unsigned int num = 0;
    for (int i = 0; i < NUM_BITS; i++) {
        num |=
            static_cast<unsigned int>(
                client_node.crypto_system().get_float_from_plaintext(*pt.at(i)))
            << i;
        delete ct.at(i);
        delete pt.at(i);
    }

    return num;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_and(
    ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2) {
    auto serialized_ct1 = client_node.crypto_system().serialize_ciphertext(ct1);
    auto serialized_ct2 = client_node.crypto_system().serialize_ciphertext(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic AND failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext(res->data());
    delete res;
    return res_ct;
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_and(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2) {
    Tensor<typename CryptoSystem::CipherText*> ct1_tensor(NUM_BITS, nullptr),
        ct2_tensor(NUM_BITS, nullptr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (int i = 0; i < NUM_BITS; i++) {
        ct1_tensor.at(i) = new typename CryptoSystem::CipherText(ct1[i]);
        ct2_tensor.at(i) = new typename CryptoSystem::CipherText(ct2[i]);
    }
    auto serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct1_tensor);
    auto serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct2_tensor);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic AND failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext_tensor(res->data());
    delete res;
    Vector<typename CryptoSystem::CipherText> res_vec;
    for (int i = 0; i < NUM_BITS; i++) {
        res_vec.push_back(*res_ct.at(i));
        delete ct1_tensor.at(i);
        delete ct2_tensor.at(i);
        delete res_ct.at(i);
    }
    return res_vec;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_or(
    ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2) {
    auto add = client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1, ct2);

    auto serialized_ct1 = client_node.crypto_system().serialize_ciphertext(ct1);
    auto serialized_ct2 = client_node.crypto_system().serialize_ciphertext(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic OR failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext(res->data());
    delete res;

    auto neg_mul = client_node.crypto_system().scal_ciphertext(
        client_node.network_public_key(),
        client_node.crypto_system().make_plaintext(-1), res_ct);

    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), add, neg_mul);
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_or(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2) {
    Tensor<typename CryptoSystem::PlainText*> pt_neg_one(NUM_BITS, nullptr);
    Tensor<typename CryptoSystem::CipherText*> ct1_tensor(NUM_BITS, nullptr),
        ct2_tensor(NUM_BITS, nullptr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (int i = 0; i < NUM_BITS; i++) {
        pt_neg_one.at(i) = new CryptoSystem::PlainText(
            client_node.crypto_system().make_plaintext(-1));
        ct1_tensor.at(i) = new typename CryptoSystem::CipherText(ct1[i]);
        ct2_tensor.at(i) = new typename CryptoSystem::CipherText(ct2[i]);
    }
    auto add = client_node.crypto_system().add_ciphertext_tensors(
        client_node.network_public_key(), ct1_tensor, ct2_tensor);
    auto serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct1_tensor);
    auto serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct2_tensor);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic OR failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext_tensor(res->data());
    delete res;

    auto neg_mul = client_node.crypto_system().scal_ciphertext_tensors(
        client_node.network_public_key(), pt_neg_one, res_ct);

    auto or_res = client_node.crypto_system().add_ciphertext_tensors(
        client_node.network_public_key(), add, neg_mul);

    Vector<typename CryptoSystem::CipherText> res_vec;
    for (int i = 0; i < NUM_BITS; i++) {
        res_vec.push_back(*or_res.at(i));
        delete pt_neg_one.at(i);
        delete ct1_tensor.at(i);
        delete ct2_tensor.at(i);
        delete add.at(i);
        delete res_ct.at(i);
        delete neg_mul.at(i);
        delete or_res.at(i);
    }

    return res_vec;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_not(
    ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct) {
    auto enc_one = client_node.crypto_system().encrypt(
        client_node.network_public_key(),
        client_node.crypto_system().make_plaintext(1));
    auto neg_ct = client_node.crypto_system().scal_ciphertext(
        client_node.network_public_key(),
        client_node.crypto_system().make_plaintext(-1), ct);
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), enc_one, neg_ct);
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_not(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct) {
    Vector<typename CryptoSystem::CipherText> res;
    Tensor<typename CryptoSystem::PlainText*> pt_one(NUM_BITS, nullptr),
        pt_neg_one(NUM_BITS, nullptr);
    Tensor<typename CryptoSystem::CipherText*> ct_tensor(NUM_BITS, nullptr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (int i = 0; i < NUM_BITS; i++) {
        pt_one.at(i) = new CryptoSystem::PlainText(
            client_node.crypto_system().make_plaintext(1));
        pt_neg_one.at(i) = new CryptoSystem::PlainText(
            client_node.crypto_system().make_plaintext(-1));
        ct_tensor.at(i) = new typename CryptoSystem::CipherText(ct[i]);
    }
    auto enc_one = client_node.crypto_system().encrypt_tensor(
        client_node.network_public_key(), pt_one);
    auto neg_ct = client_node.crypto_system().scal_ciphertext_tensors(
        client_node.network_public_key(), pt_neg_one, ct_tensor);
    auto add = client_node.crypto_system().add_ciphertext_tensors(
        client_node.network_public_key(), enc_one, neg_ct);
    for (int i = 0; i < NUM_BITS; i++) {
        res.push_back(*add.at(i));
        delete pt_one.at(i);
        delete pt_neg_one.at(i);
        delete ct_tensor.at(i);
        delete enc_one.at(i);
        delete neg_ct.at(i);
        delete add.at(i);
    }
    return res;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_xor(
    ClientNode<CryptoSystem>& client_node,
    const typename CryptoSystem::CipherText& ct1,
    const typename CryptoSystem::CipherText& ct2) {
    auto add = client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), ct1, ct2);

    auto serialized_ct1 = client_node.crypto_system().serialize_ciphertext(ct1);
    auto serialized_ct2 = client_node.crypto_system().serialize_ciphertext(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::SINGLE,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic XOR failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext(res->data());
    delete res;

    auto neg_mul = client_node.crypto_system().scal_ciphertext(
        client_node.network_public_key(),
        client_node.crypto_system().make_plaintext(-2), res_ct);
    return client_node.crypto_system().add_ciphertexts(
        client_node.network_public_key(), add, neg_mul);
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_xor(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2) {
    Tensor<typename CryptoSystem::PlainText*> pt_neg_two(NUM_BITS, nullptr);
    Tensor<typename CryptoSystem::CipherText*> ct1_tensor(NUM_BITS, nullptr),
        ct2_tensor(NUM_BITS, nullptr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (int i = 0; i < NUM_BITS; i++) {
        pt_neg_two.at(i) = new CryptoSystem::PlainText(
            client_node.crypto_system().make_plaintext(-2));
        ct1_tensor.at(i) = new typename CryptoSystem::CipherText(ct1[i]);
        ct2_tensor.at(i) = new typename CryptoSystem::CipherText(ct2[i]);
    }
    auto add = client_node.crypto_system().add_ciphertext_tensors(
        client_node.network_public_key(), ct1_tensor, ct2_tensor);
    auto serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct1_tensor);
    auto serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct2_tensor);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (!res || res->status() != ComputeResponse::Status::OK) {
        throw std::runtime_error("Homomorphic XOR failed.");
    }

    auto res_ct =
        client_node.crypto_system().deserialize_ciphertext_tensor(res->data());
    delete res;

    auto neg_mul = client_node.crypto_system().scal_ciphertext_tensors(
        client_node.network_public_key(), pt_neg_two, res_ct);

    auto xor_res = client_node.crypto_system().add_ciphertext_tensors(
        client_node.network_public_key(), add, neg_mul);

    Vector<typename CryptoSystem::CipherText> res_vec;
    for (int i = 0; i < NUM_BITS; i++) {
        res_vec.push_back(*xor_res.at(i));
        delete pt_neg_two.at(i);
        delete ct1_tensor.at(i);
        delete ct2_tensor.at(i);
        delete add.at(i);
        delete res_ct.at(i);
        delete neg_mul.at(i);
        delete xor_res.at(i);
    }

    return res_vec;
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_add(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2) {
    Vector<typename CryptoSystem::CipherText> res;
    auto carry = homomorphic_and(client_node, ct1[0], ct2[0]);
    res.push_back(homomorphic_xor(client_node, ct1[0], ct2[0]));
    for (int i = 1; i < NUM_BITS; i++) {
        auto a_and_b = homomorphic_and(client_node, ct1[i], ct2[i]);
        // auto a_and_b = homomorphic_and(client_node, ct1[i], ct2[i]);
        // saves one extra mul
        auto a_plus_b = client_node.crypto_system().add_ciphertexts(
            client_node.network_public_key(), ct1[i], ct2[i]);
        auto a_mul_b_scaled_by_neg_2 =
            client_node.crypto_system().scal_ciphertext(
                client_node.network_public_key(),
                client_node.crypto_system().make_plaintext(-2), a_and_b);
        auto a_xor_b = client_node.crypto_system().add_ciphertexts(
            client_node.network_public_key(), a_plus_b,
            a_mul_b_scaled_by_neg_2);
        auto a_xor_b_and_carry = homomorphic_and(client_node, a_xor_b, carry);
        res.push_back(homomorphic_xor(client_node, a_xor_b, carry));
        carry = homomorphic_or(client_node, a_and_b, a_xor_b_and_carry);
    }
    return res;
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_2s_complement(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct) {
    auto enc_one_bitwise = encrypt_bitwise(client_node.crypto_system(),
                                           client_node.network_public_key(), 1);
    auto ones_complement = homomorphic_not(client_node, ct);
    return homomorphic_add(client_node, enc_one_bitwise, ones_complement);
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline homomorphic_sub(
    ClientNode<CryptoSystem>& client_node,
    const Vector<typename CryptoSystem::CipherText>& ct1,
    const Vector<typename CryptoSystem::CipherText>& ct2) {
    // return homomorphic_add(client_node, ct1,
    // homomorphic_2s_complement(client_node, ct2));
    Vector<typename CryptoSystem::CipherText> res;
    auto neg_ct1 = homomorphic_not(client_node, ct1);
    auto borrow = homomorphic_and(client_node, ct2[0], neg_ct1[0]);
    res.push_back(homomorphic_xor(client_node, ct1[0], ct2[0]));
    for (int i = 1; i < NUM_BITS; i++) {
        auto a_xor_b = homomorphic_xor(client_node, ct1[i], ct2[i]);
        auto not_a_xor_b = homomorphic_not(client_node, a_xor_b);
        auto b_in_and_not_a_xor_b =
            homomorphic_and(client_node, borrow, not_a_xor_b);
        auto not_a_and_b = homomorphic_and(client_node, ct2[i], neg_ct1[i]);
        res.push_back(homomorphic_xor(client_node, a_xor_b, borrow));
        borrow = homomorphic_or(client_node, b_in_and_not_a_xor_b, not_a_and_b);
    }
    return res;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_lt(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2) {
    auto neg_ct1 = homomorphic_not(client_node, ct1);
    auto borrow = homomorphic_and(client_node, ct2[0], neg_ct1[0]);
    for (int i = 1; i < NUM_BITS; i++) {
        auto a_xor_b = homomorphic_xor(client_node, ct1[i], ct2[i]);
        auto not_a_xor_b = homomorphic_not(client_node, a_xor_b);
        auto b_in_and_not_a_xor_b =
            homomorphic_and(client_node, borrow, not_a_xor_b);
        auto not_a_and_b = homomorphic_and(client_node, ct2[i], neg_ct1[i]);
        borrow = homomorphic_or(client_node, b_in_and_not_a_xor_b, not_a_and_b);
    }
    return borrow;
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_eq(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2) {
    auto sub = homomorphic_sub(client_node, ct1, ct2);
    typename CryptoSystem::CipherText sub_bits_sum = sub[0];
    for (int i = 1; i < NUM_BITS; i++) {
        sub_bits_sum = homomorphic_or(client_node, sub_bits_sum, sub[i]);
    }
    return homomorphic_not(client_node, sub_bits_sum);
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline homomorphic_gt(
    ClientNode<CryptoSystem>& client_node,
    Vector<typename CryptoSystem::CipherText>& ct1,
    Vector<typename CryptoSystem::CipherText>& ct2) {
    return homomorphic_lt(client_node, ct2, ct1);
}

template <typename CryptoSystem>
std::string inline serialize_bit(const CryptoSystem& cs,
                                 const typename CryptoSystem::CipherText& ct) {
    return cs.serialize_ciphertext(ct);
}

template <typename CryptoSystem>
typename CryptoSystem::CipherText inline deserialize_bit(
    const CryptoSystem& cs, const std::string& serialized) {
    return cs.deserialize_ciphertext(serialized);
}

template <typename CryptoSystem>
std::string inline serialize_bitwise(
    const CryptoSystem& cs,
    const Vector<typename CryptoSystem::CipherText>& cts) {
    //  NUM_BITS*8 bytes are used to represent the size of each ciphertext
    // the size of each ciphertext is stored before the ciphertext
    // the rest of the bytes are the ciphertexts
    // this and deserialization funcs can be further optimized if needed
    std::vector<std::string> serialized_cts;
    for (int i = 0; i < NUM_BITS; i++) {
        serialized_cts.push_back(cs.serialize_ciphertext(cts[i]));
    }
    uint64_t total_size = NUM_BITS * sizeof(uint64_t);
    for (int i = 0; i < NUM_BITS; i++) {
        total_size += serialized_cts[i].size();
    }
    std::string serialized(total_size, 0);
    char* data_ptr = serialized.data();
    for (int i = 0; i < NUM_BITS; i++) {
        uint64_t size_of_ct = serialized_cts[i].size();
        memcpy(data_ptr, &size_of_ct, sizeof(uint64_t));
        data_ptr += sizeof(uint64_t);
        memcpy(data_ptr, serialized_cts[i].data(), size_of_ct);
        data_ptr += size_of_ct;
    }
    return serialized;
}

template <typename CryptoSystem>
Vector<typename CryptoSystem::CipherText> inline deserialize_bitwise(
    const CryptoSystem& cs, const std::string& serialized) {
    Vector<typename CryptoSystem::CipherText> cts;
    const char* data_ptr = serialized.data();
    for (int i = 0; i < NUM_BITS; i++) {
        uint64_t size_of_ct;
        memcpy(&size_of_ct, data_ptr, sizeof(uint64_t));
        data_ptr += sizeof(uint64_t);
        std::string ct_str(data_ptr, size_of_ct);
        cts.push_back(cs.deserialize_ciphertext(ct_str));
        data_ptr += size_of_ct;
    }
    return cts;
}