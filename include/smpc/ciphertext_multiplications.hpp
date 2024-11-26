#ifndef CoFHE_SMPC_CIPHERTEXT_MULTIPLICATIONS_HPP_INCLUDED
#define CoFHE_SMPC_CIPHERTEXT_MULTIPLICATIONS_HPP_INCLUDED

#include "smpc/smpc_client.hpp"

namespace CoFHE
{
    template <typename CryptoSystem>
    class SMPCCipherTextMultiplier
    {
    public:
        using CipherText = typename CryptoSystem::CipherText;

        SMPCCipherTextMultiplier(SMPCClient<CryptoSystem> &client) : client_m(client) {}

        CipherText multiply_ciphertexts(CipherText ct1, CipherText ct2)
        {
            auto triplets = client_m.get_beavers_triplets(1);
            auto a = *triplets.at(0, 0);
            auto b = *triplets.at(0, 1);
            auto neg_a = client_m.crypto_system().negate_ciphertext(client_m.network_public_key(), a);
            auto neg_b = client_m.crypto_system().negate_ciphertext(client_m.network_public_key(), b);
            auto c = *triplets.at(0, 2);
            auto ct1_neg_a = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), ct1, neg_a);
            auto ct2_neg_b = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), ct2, neg_b);
            auto pt1 = client_m.decrypt(ct1_neg_a);
            auto pt2 = client_m.decrypt(ct2_neg_b);
            auto pt1_pt2 = client_m.crypto_system().multiply_plaintexts(pt1, pt2);
            auto enc_pt1_pt2 = client_m.crypto_system().encrypt(client_m.network_public_key(), pt1_pt2);
            auto pt1_b = client_m.crypto_system().scal_ciphertext(client_m.network_public_key(), pt1, b);
            auto pt2_a = client_m.crypto_system().scal_ciphertext(client_m.network_public_key(), pt2, a);
            auto ct = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), pt1_b, pt2_a);
            ct = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), ct, c);
            ct = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), ct, enc_pt1_pt2);
            delete triplets.at(0, 0);
            delete triplets.at(0, 1);
            delete triplets.at(0, 2);
            return ct;
        }

        Tensor<CipherText *> multiply_ciphertext_tensors(Tensor<CipherText *> ct1, Tensor<CipherText *> ct2)
        {
            if (ct1.is_zero_degree() && ct2.is_zero_degree())
            {
                return Tensor<CipherText *>(new CipherText(multiply_ciphertexts(*ct1.get_value(), *ct2.get_value())));
            }
            if (ct1.ndim() == 1)
            {
                return handle_vector_ciphertext_mul(ct1, ct2);
            }
            if (ct1.ndim() == 2)
            {
                // Calculate all n*m*p ciphertext multiplication in parallel
                size_t n = ct1.shape()[0], m = ct1.shape()[1], p = ct2.shape()[1], nmp = n * m * p;
                Tensor<CipherText *> ct1_nmp(nmp,nullptr), ct2_nmp(nmp,nullptr);
                auto ct1_flattened = ct1;
                ct1_flattened.flatten();
                auto ct2_flattened = ct2;
                ct2_flattened.flatten();
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = 0; i < n; i++)
                {
                    for (size_t j = 0; j < m; j++)
                    {
                        for (size_t k =0; k < p; k++)
                        {
                            ct1_nmp.at(i*m*p + j*p + k) = ct1_flattened.at(i*m+j);
                            ct2_nmp.at(i*m*p + j*p + k) = ct2_flattened.at(j*p+k);
                        }
                    }
                }
                // this contains the result of the multiplication of each element of ct1 with each element of required row of ct2
                // the first p elements of res_nmp are the result of the multiplication of the first element of ct1 with each element of the first row of ct2
                // and so on
                auto res_nmp = handle_vector_ciphertext_mul(ct1_nmp, ct2_nmp);
                // now sum these results to get the final result
                Tensor<CipherText *> res(n*p,nullptr);
                // initi with zero
                auto zero = client_m.crypto_system().encrypt(client_m.network_public_key(), client_m.crypto_system().make_plaintext(0));
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = 0; i < n*p; i++){
                    res.at(i) = new CipherText(zero);   
                }
    
                auto cl_g = client_m.crypto_system().get_hsm2k().Cl_G();
                auto cl_delta = client_m.crypto_system().get_hsm2k().Cl_Delta();
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2
                for (size_t i = 0; i < n; i++)
                {
                    for (size_t k =0; k < p; k++)
                    {
                        for (size_t j = 0; j < m; j++)
                        {
                            // auto new_res = client_m.crypto_system().add_ciphertexts(client_m.network_public_key(), *res.at(i*p+k), *res_nmp.at(i*m*p + j*p + k));
                            // delete res.at(i*p+k);
                            // res.at(i*p+k) = new CipherText(new_res);
                            cl_g.nucomp(res.at(i*p+k)->c1(), res.at(i*p+k)->c1(), res_nmp.at(i*m*p + j*p + k)->c1());
                            cl_delta.nucomp(res.at(i*p+k)->c2(), res.at(i*p+k)->c2(), res_nmp.at(i*m*p + j*p + k)->c2());
                        }
                    }
                }
                
                CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
                for (size_t i = 0; i < nmp; i++)
                {
                    delete res_nmp.at(i);
                }

                res.reshape({n,p});
                return res;
            }
            throw std::runtime_error("Not implemented");
        }

        Tensor<CipherText *> handle_vector_ciphertext_mul(const Tensor<CipherText *> &ct1, const Tensor<CipherText *> &ct2)
        {
            auto triplets = client_m.get_beavers_triplets(ct1.shape()[0]);
            Tensor<CipherText *> res(ct1.shape(), nullptr);
            Tensor<CipherText *> a_tensor(ct1.shape(), nullptr), b_tensor(ct1.shape(), nullptr), c_tensor(ct1.shape(), nullptr);
            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < ct1.shape()[0]; i++)
            {
                a_tensor.at(i) = triplets.at(i, 0);
                b_tensor.at(i) = triplets.at(i, 1);
                c_tensor.at(i) = triplets.at(i, 2);
            }
            auto neg_a_tensor = client_m.crypto_system().negate_ciphertext_tensor(client_m.network_public_key(), a_tensor);
            auto neg_b_tensor = client_m.crypto_system().negate_ciphertext_tensor(client_m.network_public_key(), b_tensor);
            auto ct1_neg_a = client_m.crypto_system().add_ciphertext_tensors(client_m.network_public_key(), ct1, neg_a_tensor);
            auto ct2_neg_b = client_m.crypto_system().add_ciphertext_tensors(client_m.network_public_key(), ct2, neg_b_tensor);
            auto pt1 = client_m.decrypt_tensor(ct1_neg_a);
            auto pt2 = client_m.decrypt_tensor(ct2_neg_b);
            auto pt1_pt2 = client_m.crypto_system().multiply_plaintext_tensors(pt1, pt2);
            auto enc_pt1_pt2 = client_m.crypto_system().encrypt_tensor(client_m.network_public_key(), pt1_pt2);
            auto pt1_b = client_m.crypto_system().scal_ciphertext_tensors(client_m.network_public_key(), pt1, b_tensor);
            auto pt2_a = client_m.crypto_system().scal_ciphertext_tensors(client_m.network_public_key(), pt2, a_tensor);
            auto ct = client_m.crypto_system().add_ciphertext_tensors(client_m.network_public_key(), pt1_b, pt2_a);
            ct = client_m.crypto_system().add_ciphertext_tensors(client_m.network_public_key(), ct, c_tensor);
            ct = client_m.crypto_system().add_ciphertext_tensors(client_m.network_public_key(), ct, enc_pt1_pt2);


            CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
            for (size_t i = 0; i < ct1.shape()[0]; i++)
            {
                delete triplets.at(i, 0);
                delete triplets.at(i, 1);
                delete triplets.at(i, 2);
                delete neg_a_tensor.at(i);
                delete neg_b_tensor.at(i);
                delete  ct1_neg_a.at(i);
                delete  ct2_neg_b.at(i);
                delete  pt1.at(i);
                delete  pt2.at(i);
                delete  pt1_pt2.at(i);
                delete  enc_pt1_pt2.at(i);
                delete  pt1_b.at(i);
                delete  pt2_a.at(i);
            }
            return ct;
        }

    private:
        SMPCClient<CryptoSystem> &client_m;
    };
} // namespace CoFHE

#endif