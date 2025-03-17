#include <chrono>
#include <iostream>
#include <vector>

#include "cofhe.hpp"

// #define DEBUG_PRINT 1

using namespace CoFHE;

int get_nth_bit(int num, int n) { return (num >> n) & 1; }

int get_n_from_bits(std::vector<int> bits) {
    int num = 0;
    for (int i = 0; i < bits.size(); i++) {
        num |= bits[i] << i;
    }
    return num;
}

std::vector<Tensor<CPUCryptoSystem::CipherText*>>
encrypt_tensor_bitwise(CPUCryptoSystem& cs, CPUCryptoSystem::PublicKey& pk,
                       std::vector<int> nums) {
    std::vector<Tensor<CPUCryptoSystem::CipherText*>> cts;
    for (int i = 0; i < 32; i++) {
        Tensor<CPUCryptoSystem::PlainText*> pt(nums.size(), 1, nullptr);
        for (int j = 0; j < nums.size(); j++) {
            pt.at(j, 0) = new CPUCryptoSystem::PlainText(
                cs.make_plaintext(get_nth_bit(nums[j], i)));
        }
        cts.push_back(cs.encrypt_tensor(pk, pt));
    }
    return cts;
}

std::vector<int> decrypt_bits(ClientNode<CPUCryptoSystem>& client_node,
                              Tensor<CPUCryptoSystem::CipherText*>& ct) {

    std::string serialized_ct =
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

    if (res && res->status() == ComputeResponse::Status::OK) {
        auto pt = client_node.crypto_system().deserialize_plaintext_tensor(
            res->data());
        std::vector<int> bits;
        for (int i = 0; i < pt.size(); i++) {
            bits.push_back(static_cast<int>(
                client_node.crypto_system().get_float_from_plaintext(
                    *pt.at(i, 0))));
        }
        for (int i = 0; i < pt.size(); i++) {
            delete pt.at(i, 0);
        }
        return bits;
    } else {
        std::cerr << "Decryption failed." << std::endl;
        std::exit(1);
    }
}

std::vector<int>
decrypt_tensor_bitwise(ClientNode<CPUCryptoSystem>& client_node,
                       std::vector<Tensor<CPUCryptoSystem::CipherText*>>& cts) {
    std::vector<int> nums;
    std::vector<std::vector<int>> bits;
    for (int i = 0; i < 32; i++) {
        bits.push_back(decrypt_bits(client_node, cts[i]));
    }
    std::vector<std::vector<int>> bits_per_num;
    for (int i = 0; i < bits[0].size(); ++i) {
        std::vector<int> curr_num_bits;
        for (int j = 0; j < 32; ++j) {
            curr_num_bits.push_back(bits[j][i]);
        }
        bits_per_num.push_back(curr_num_bits);
    }
    for (int i = 0; i < bits_per_num.size(); i++) {
        nums.push_back(get_n_from_bits(bits_per_num[i]));
    }
    return nums;
}

void debug_print(ClientNode<CPUCryptoSystem>& client_node,
                 Tensor<CPUCryptoSystem::CipherText*>& ct, std::string msg) {
#ifdef DEBUG_PRINT
    std::cout << msg << std::endl;
    auto bits = decrypt_bits(client_node, ct);
    for (int i = 0; i < bits.size(); i++) {
        std::cout << bits[i];
    }
    std::cout << std::endl;
#endif
}

Tensor<CPUCryptoSystem::CipherText*>
add(ClientNode<CPUCryptoSystem>& client_node,
    Tensor<CPUCryptoSystem::CipherText*>& ct1,
    Tensor<CPUCryptoSystem::CipherText*>& ct2) {
    std::string serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct1);
    std::string serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct2);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct1);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct2);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::ADD, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    if (res && res->status() == ComputeResponse::Status::OK) {
        return client_node.crypto_system().deserialize_ciphertext_tensor(
            res->data());
    } else {
        std::cerr << "Homomorphic AND failed." << std::endl;
        std::exit(1);
    }
}

Tensor<CPUCryptoSystem::CipherText*>
multiply_by_k(ClientNode<CPUCryptoSystem>& client_node,
              Tensor<CPUCryptoSystem::CipherText*>& ct, int k) {
    Tensor<CPUCryptoSystem::PlainText*> pt(ct.size(), 1, nullptr);
    for (int i = 0; i < ct.size(); i++) {
        pt.at(i, 0) = new CPUCryptoSystem::PlainText(
            client_node.crypto_system().make_plaintext(k));
    }

    std::string serialized_pt =
        client_node.crypto_system().serialize_plaintext_tensor(pt);
    std::string serialized_ct =
        client_node.crypto_system().serialize_ciphertext_tensor(ct);

    ComputeRequest::ComputeOperationOperand operand1(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::PLAINTEXT, serialized_pt);

    ComputeRequest::ComputeOperationOperand operand2(
        ComputeRequest::DataType::TENSOR,
        ComputeRequest::DataEncrytionType::CIPHERTEXT, serialized_ct);

    ComputeRequest::ComputeOperationInstance operation(
        ComputeRequest::ComputeOperationType::BINARY,
        ComputeRequest::ComputeOperation::MULTIPLY, {operand1, operand2});

    ComputeRequest req(operation);
    ComputeResponse* res;

    client_node.compute(req, &res);

    for (int i = 0; i < ct.size(); i++) {
        delete pt.at(i, 0);
    }

    if (res && res->status() == ComputeResponse::Status::OK) {
        return client_node.crypto_system().deserialize_ciphertext_tensor(
            res->data());
    } else {
        std::cerr << "Homomorphic AND failed." << std::endl;
        std::exit(1);
    }
}

Tensor<CPUCryptoSystem::CipherText*>
multiply(ClientNode<CPUCryptoSystem>& client_node,
         Tensor<CPUCryptoSystem::CipherText*>& ct1,
         Tensor<CPUCryptoSystem::CipherText*>& ct2) {
    std::string serialized_ct1 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct1);
    std::string serialized_ct2 =
        client_node.crypto_system().serialize_ciphertext_tensor(ct2);

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

    if (res && res->status() == ComputeResponse::Status::OK) {
        return client_node.crypto_system().deserialize_ciphertext_tensor(
            res->data());
    } else {
        std::cerr << "Homomorphic AND failed." << std::endl;
        std::exit(1);
    }
}

Tensor<CPUCryptoSystem::CipherText*>
homorphic_or(ClientNode<CPUCryptoSystem>& client_node,
             Tensor<CPUCryptoSystem::CipherText*>& ct1,
             Tensor<CPUCryptoSystem::CipherText*>& ct2) {
    auto a_plus_b = add(client_node, ct1, ct2);
    auto a_mul_b = multiply(client_node, ct1, ct2);
    auto neg_a_mul_b = multiply_by_k(client_node, a_mul_b, -1);
    auto res = add(client_node, a_plus_b, neg_a_mul_b);
    for (int i = 0; i < a_plus_b.size(); i++) {
        delete a_plus_b.at(i, 0);
        delete a_mul_b.at(i, 0);
        delete neg_a_mul_b.at(i, 0);
    }
    return res;
}

Tensor<CPUCryptoSystem::CipherText*>
homorphic_and(ClientNode<CPUCryptoSystem>& client_node,
              Tensor<CPUCryptoSystem::CipherText*>& ct1,
              Tensor<CPUCryptoSystem::CipherText*>& ct2) {
    // just multiply the two ciphertexts
    return multiply(client_node, ct1, ct2);
}

Tensor<CPUCryptoSystem::CipherText*>
homorphic_not(ClientNode<CPUCryptoSystem>& client_node,
              Tensor<CPUCryptoSystem::CipherText*>& ct) {
    auto neg_ct = multiply_by_k(client_node, ct, -1);
    auto one = client_node.crypto_system().encrypt(
        client_node.network_public_key(),
        client_node.crypto_system().make_plaintext(1));
    Tensor<CPUCryptoSystem::CipherText*> ct_one(ct.size(), 1, nullptr);
    for (int i = 0; i < ct.size(); i++) {
        ct_one.at(i, 0) = new CPUCryptoSystem::CipherText(one);
    }
    auto res = add(client_node, ct_one, neg_ct);
    for (int i = 0; i < ct.size(); i++) {
        delete neg_ct.at(i, 0);
        delete ct_one.at(i, 0);
    }
    return res;
}

Tensor<CPUCryptoSystem::CipherText*>
homorphic_xor(ClientNode<CPUCryptoSystem>& client_node,
              Tensor<CPUCryptoSystem::CipherText*>& ct1,
              Tensor<CPUCryptoSystem::CipherText*>& ct2) {
    auto a_plus_b = add(client_node, ct1, ct2);
    auto a_mul_b = multiply(client_node, ct1, ct2);
    auto two_a_mul_b = multiply_by_k(client_node, a_mul_b, -2);
    auto res = add(client_node, a_plus_b, two_a_mul_b);
    for (int i = 0; i < a_plus_b.size(); i++) {
        delete a_plus_b.at(i, 0);
        delete a_mul_b.at(i, 0);
        delete two_a_mul_b.at(i, 0);
    }
    return res;
}

std::vector<Tensor<CPUCryptoSystem::CipherText*>>
homorphic_add_for_bitwise_encrypted_32bit_nums(
    ClientNode<CPUCryptoSystem>& client_node,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct1,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct2) {
    std::vector<Tensor<CPUCryptoSystem::CipherText*>> res;
    auto carry = homorphic_and(client_node, ct1[0], ct2[0]);
    res.push_back(homorphic_xor(client_node, ct1[0], ct2[0]));
    for (int i = 1; i < 32; i++) {
        auto carry_next = homorphic_and(client_node, ct1[i], ct2[i]);
        debug_print(client_node, carry_next, "carry_next");
        auto sum = homorphic_xor(client_node, ct1[i], ct2[i]);
        debug_print(client_node, sum, "sum");
        auto carry_sum = homorphic_and(client_node, sum, carry);
        debug_print(client_node, carry_sum, "carry_sum");
        auto sum_carry = homorphic_xor(client_node, sum, carry);
        debug_print(client_node, sum_carry, "sum_carry");
        for (int j = 0; j < carry.size(); j++) {
            delete carry.at(j, 0);
        }
        carry = homorphic_or(client_node, carry_next, carry_sum);
        debug_print(client_node, carry, "carry");
        res.push_back(sum_carry);
        for (int j = 0; j < carry.size(); j++) {
            delete carry_next.at(j, 0);
            delete sum.at(j, 0);
            delete carry_sum.at(j, 0);
        }
    }
    for (int i = 0; i < carry.size(); i++) {
        delete carry.at(i, 0);
    }
    return res;
}

std::vector<Tensor<CPUCryptoSystem::CipherText*>>
homorphic_sub_for_bitwise_encrypted_32bit_nums(
    ClientNode<CPUCryptoSystem>& client_node,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct1,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct2,
    bool return_borrow = false) {
    std::vector<Tensor<CPUCryptoSystem::CipherText*>> res;
    auto borrow = homorphic_and(client_node, ct1[0], ct2[0]);
    res.push_back(homorphic_xor(client_node, ct1[0], ct2[0]));
    for (int i = 1; i < 32; i++) {
        auto diff = homorphic_xor(client_node, ct1[i], ct2[i]);
        auto not_diff = homorphic_not(client_node, diff);
        auto not_diff_and_borrow = homorphic_and(client_node, not_diff, borrow);
        auto diff_borrow = homorphic_xor(client_node, diff, borrow);
        auto not_a = homorphic_not(client_node, ct1[i]);
        auto not_a_and_b = homorphic_and(client_node, not_a, ct2[i]);
        for (int j = 0; j < borrow.size(); j++) {
            delete borrow.at(j, 0);
        }
        borrow = homorphic_or(client_node, not_diff_and_borrow, not_a_and_b);
        res.push_back(diff_borrow);
        for (int j = 0; j < borrow.size(); j++) {
            delete diff.at(j, 0);
            delete not_diff.at(j, 0);
            delete not_diff_and_borrow.at(j, 0);
            delete not_a.at(j, 0);
            delete not_a_and_b.at(j, 0);
        }
    }
    if (return_borrow) {
        std::vector<Tensor<CPUCryptoSystem::CipherText*>> res_b;
        res_b.push_back(borrow);
        return res_b;
    }

    for (int i = 0; i < borrow.size(); i++) {
        delete borrow.at(i, 0);
    }
    return res;
}

// true means ct1 > ct2
std::vector<bool> homorphic_comparision_for_bitwise_encrypted_32bit_nums(
    ClientNode<CPUCryptoSystem>& client_node,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct1,
    std::vector<Tensor<CPUCryptoSystem::CipherText*>>& ct2) {
    auto diff = homorphic_sub_for_bitwise_encrypted_32bit_nums(client_node, ct1,
                                                               ct2, true);
    std::vector<bool> res;
    auto msb_res = decrypt_bits(client_node, diff[0]);
    for (int i = 0; i < msb_res.size(); ++i) {
        if (msb_res[i] == 1) {
            res.push_back(false);
        } else {
            res.push_back(true);
        }
    }
    return res;
}

void test_bitwise_encryption_decryption(
    ClientNode<CPUCryptoSystem>& client_node) {
    std::vector<int> nums = {1, 2, 3, 4};
    auto pk = client_node.network_public_key();
    auto cts = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums);
    auto decrypted_nums = decrypt_tensor_bitwise(client_node, cts);
    for (int i = 0; i < decrypted_nums.size(); i++) {
        std::cout << nums[i] << " = " << decrypted_nums[i] << std::endl;
    }
}

void test_or(ClientNode<CPUCryptoSystem>& client_node) {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            std::vector<int> nums1 = {i};
            std::vector<int> nums2 = {j};
            auto pk = client_node.network_public_key();
            auto cts1 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
            auto cts2 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
            auto res = homorphic_or(client_node, cts1[0], cts2[0]);
            auto decrypted_res = decrypt_bits(client_node, res);
            std::cout << nums1[0] << " OR " << nums2[0] << " = "
                      << decrypted_res[0] << "Actual: " << (nums1[0] | nums2[0])
                      << std::endl;
        }
    }
}

void test_and(ClientNode<CPUCryptoSystem>& client_node) {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            std::vector<int> nums1 = {i};
            std::vector<int> nums2 = {j};
            auto pk = client_node.network_public_key();
            auto cts1 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
            auto cts2 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
            auto res = homorphic_and(client_node, cts1[0], cts2[0]);
            auto decrypted_res = decrypt_bits(client_node, res);
            std::cout << nums1[0] << " AND " << nums2[0] << " = "
                      << decrypted_res[0] << "Actual: " << (nums1[0] & nums2[0])
                      << std::endl;
        }
    }
}

void test_not(ClientNode<CPUCryptoSystem>& client_node) {
    for (int i = 0; i < 2; i++) {
        std::vector<int> nums = {i};
        auto pk = client_node.network_public_key();
        auto cts =
            encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums);
        auto res = homorphic_not(client_node, cts[0]);
        auto decrypted_res = decrypt_bits(client_node, res);
        std::cout << "NOT " << nums[0] << " = " << decrypted_res[0]
                  << "Actual: " << (nums[0] == 0 ? 1 : 0) << std::endl;
    }
}

void test_xor(ClientNode<CPUCryptoSystem>& client_node) {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            std::vector<int> nums1 = {i};
            std::vector<int> nums2 = {j};
            auto pk = client_node.network_public_key();
            auto cts1 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
            auto cts2 =
                encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
            auto res = homorphic_xor(client_node, cts1[0], cts2[0]);
            auto decrypted_res = decrypt_bits(client_node, res);
            std::cout << nums1[0] << " XOR " << nums2[0] << " = "
                      << decrypted_res[0] << "Actual: " << (nums1[0] ^ nums2[0])
                      << std::endl;
        }
    }
}

void test_addition(ClientNode<CPUCryptoSystem>& client_node) {
    // std::vector<int> nums1 = {1, 2, 3, 4};
    // std::vector<int> nums2 = {2, 1, 4, 3};
    std::vector<int> nums1 = {22};
    std::vector<int> nums2 = {13};
    auto pk = client_node.network_public_key();
    auto cts1 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
    auto cts2 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
    auto res =
        homorphic_add_for_bitwise_encrypted_32bit_nums(client_node, cts1, cts2);
    auto decrypted_res = decrypt_tensor_bitwise(client_node, res);
    for (int i = 0; i < decrypted_res.size(); i++) {
        std::cout << nums1[i] << " + " << nums2[i] << " = " << decrypted_res[i]
                  << "Actual: " << (nums1[i] + nums2[i]) << std::endl;
    }
}

void test_subtract(ClientNode<CPUCryptoSystem>& client_node) {
    // std::vector<int> nums1 = {2, 3, 4, 5};
    // std::vector<int> nums2 = {1, 2, 3, 4};
    std::vector<int> nums1 = {17};
    std::vector<int> nums2 = {13};
    auto pk = client_node.network_public_key();
    auto cts1 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
    auto cts2 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
    auto res =
        homorphic_sub_for_bitwise_encrypted_32bit_nums(client_node, cts1, cts2);
    auto decrypted_res = decrypt_tensor_bitwise(client_node, res);
    for (int i = 0; i < decrypted_res.size(); i++) {
        std::cout << nums1[i] << " - " << nums2[i] << " = " << decrypted_res[i]
                  << "Actual: " << (nums1[i] - nums2[i]) << std::endl;
    }
}

void test_comparision(ClientNode<CPUCryptoSystem>& client_node) {
    // std::vector<int> nums1 = {1, 2, 3, 4};
    // std::vector<int> nums2 = {2, 1, 4, 3};
    std::vector<int> nums1 = {14, 13};
    std::vector<int> nums2 = {23, 12};
    auto pk = client_node.network_public_key();
    auto cts1 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums1);
    auto cts2 = encrypt_tensor_bitwise(client_node.crypto_system(), pk, nums2);
    auto res = homorphic_comparision_for_bitwise_encrypted_32bit_nums(
        client_node, cts1, cts2);
    for (int i = 0; i < res.size(); i++) {
        std::cout << nums1[i] << " > " << nums2[i] << " : " << res[i]
                  << "Actual: " << (nums1[i] > nums2[i]) << std::endl;
    }
}

void test(ClientNode<CPUCryptoSystem>& client_node) {
    auto start = std::chrono::high_resolution_clock::now(),
         end = std::chrono::high_resolution_clock::now();
    test_bitwise_encryption_decryption(client_node);
    test_or(client_node);
    test_and(client_node);
    test_not(client_node);
    test_xor(client_node);
    start = std::chrono::high_resolution_clock::now();
    test_addition(client_node);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Addition time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                      start)
                     .count()
              << "ms" << std::endl;
    start = std::chrono::high_resolution_clock::now();
    test_subtract(client_node);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Subtraction time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                      start)
                     .count()
              << "ms" << std::endl;
    start = std::chrono::high_resolution_clock::now();
    test_comparision(client_node);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Comparision time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                      start)
                     .count()
              << "ms" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <client_ip> <client_port> <setup_ip> <setup_port>"
                  << std::endl;
        return 1;
    }

    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details =
        NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    test(client_node);
    return 1;
}