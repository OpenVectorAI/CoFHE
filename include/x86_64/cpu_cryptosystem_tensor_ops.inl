inline Tensor<CPUCryptoSystem::CipherText *> CPUCryptoSystem::encrypt_tensor(const PublicKey &pk_cpu, const Tensor<CPUCryptoSystem::PlainText *> &pt_cpu) const
{
    Tensor<CPUCryptoSystem::CipherText *> ct_cpu(pt_cpu.shape(), nullptr);
    auto pt_cpu_flattened = pt_cpu;
    pt_cpu_flattened.flatten();
    ct_cpu.flatten();
    auto r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI c1, pkr;
    hsm2k.power_of_h(c1, r);
    pk_cpu.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt_cpu.num_elements(); i++)
    {
        ct_cpu.at(i) = new CPUCryptoSystem::CipherText(hsm2k, this->to_plaintext(*pt_cpu_flattened[i]), c1, pkr);
    }
    ct_cpu.reshape(pt_cpu.shape());
    return ct_cpu;
};

inline Tensor<CPUCryptoSystem::PlainText *> CPUCryptoSystem::decrypt_tensor(const SecretKey &sk_cpu, const Tensor<CPUCryptoSystem::CipherText *> &ct_cpu) const
{
    Tensor<CPUCryptoSystem::PlainText *> pt_cpu(ct_cpu.shape(), nullptr);
    auto ct_cpu_flattened = ct_cpu;
    ct_cpu_flattened.flatten();
    pt_cpu.flatten();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct_cpu.num_elements(); i++)
    {
        pt_cpu[i] = new CPUCryptoSystem::PlainText(this->decrypt(sk_cpu, *ct_cpu_flattened[i]));
    }
    pt_cpu.reshape(ct_cpu.shape());
    return pt_cpu;
};

inline Tensor<CPUCryptoSystem::PartDecryptionResult *> CPUCryptoSystem::part_decrypt_tensor(const CPUCryptoSystem::SecretKeyShare &sks_cpu, const Tensor<CPUCryptoSystem::CipherText *> &ct_cpu) const
{
    Tensor<CPUCryptoSystem::PartDecryptionResult *> pdr_cpu(ct_cpu.shape(), nullptr);
    auto ct_cpu_flattened = ct_cpu;
    ct_cpu_flattened.flatten();
    pdr_cpu.flatten();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct_cpu.num_elements(); i++)
    {
        pdr_cpu[i] = new CPUCryptoSystem::PartDecryptionResult(this->part_decrypt(sks_cpu, *ct_cpu_flattened[i]));
    }
    pdr_cpu.reshape(ct_cpu.shape());
    return pdr_cpu;
};

inline Tensor<CPUCryptoSystem::PlainText *> CPUCryptoSystem::combine_part_decryption_results_tensor(const Tensor<CPUCryptoSystem::CipherText *> &ct_cpu,
                                                                                                    const Vector<Tensor<CPUCryptoSystem::PartDecryptionResult *>> &pdrs_cpu) const
{
    Tensor<CPUCryptoSystem::PlainText *> pt_cpu(pdrs_cpu[0].shape(), nullptr);
    auto ct_cpu_flattened = ct_cpu;
    ct_cpu_flattened.flatten();
    Vector<Tensor<CPUCryptoSystem::PartDecryptionResult *>> pdrs_cpu_flattened;
    for (size_t i = 0; i < pdrs_cpu.size(); i++)
    {
        pdrs_cpu_flattened.push_back(pdrs_cpu[i]);
        pdrs_cpu_flattened[i].flatten();
    }
    pt_cpu.flatten();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct_cpu.num_elements(); i++)
    {
        Vector<CPUCryptoSystem::PartDecryptionResult> pdrs_vec(pdrs_cpu.size());
        for (size_t j = 0; j < pdrs_cpu.size(); j++)
        {
            pdrs_vec[j] = *pdrs_cpu_flattened[j][i];
        }
        pt_cpu[i] = new CPUCryptoSystem::PlainText(this->combine_part_decryption_results(*ct_cpu_flattened[i], pdrs_vec));
    }
    pt_cpu.reshape(pdrs_cpu[0].shape());
    return pt_cpu;
};

inline Tensor<CPUCryptoSystem::PlainText *> CPUCryptoSystem::add_plaintext_tensors(const Tensor<CPUCryptoSystem::PlainText *> &pt1, const Tensor<CPUCryptoSystem::PlainText *> &pt2) const
{
    if (pt1.is_zero_degree() && pt2.is_zero_degree())
    {
        return Tensor<CPUCryptoSystem::PlainText *>(new CPUCryptoSystem::PlainText(this->add_plaintexts(*pt1.get_value(), *pt2.get_value())));
    }
    if (pt1.shape() != pt2.shape())
    {
        throw std::invalid_argument("Tensor shapes must be equal");
    }
    if (pt1.ndim() == 1)
    {
        Tensor<CPUCryptoSystem::PlainText *> res(pt1.shape(), nullptr);
        res.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt1.num_elements(); i++)
        {
            res[i] = new CPUCryptoSystem::PlainText(this->add_plaintexts(*pt1[i], *pt2[i]));
        }
        res.reshape(pt1.shape());
        return res;
    }
    throw std::runtime_error("Not implemented");
}

inline Tensor<CPUCryptoSystem::PlainText *> CPUCryptoSystem::multiply_plaintext_tensors(const Tensor<CPUCryptoSystem::PlainText *> &pt1, const Tensor<CPUCryptoSystem::PlainText *> &pt2) const
{
    if (pt1.is_zero_degree() && pt2.is_zero_degree())
    {
        return Tensor<CPUCryptoSystem::PlainText *>(new CPUCryptoSystem::PlainText(this->multiply_plaintexts(*pt1.get_value(), *pt2.get_value())));
    }
    if (pt1.shape() != pt2.shape())
    {
        throw std::invalid_argument("Tensor shapes must be equal");
    }
    if (pt1.ndim() == 1)
    {
        Tensor<CPUCryptoSystem::PlainText *> res(pt1.shape(), nullptr);
        res.flatten();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pt1.num_elements(); i++)
        {
            res[i] = new CPUCryptoSystem::PlainText(this->multiply_plaintexts(*pt1[i], *pt2[i]));
        }
        res.reshape(pt1.shape());
        return res;
    }
    throw std::runtime_error("Not implemented");
}

inline Tensor<CPUCryptoSystem::PlainText *> CPUCryptoSystem::negate_plaintext_tensor(const Tensor<CPUCryptoSystem::PlainText *> &s) const
{
    Tensor<CPUCryptoSystem::PlainText *> res(s.shape(), nullptr);
    res.flatten();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < s.num_elements(); i++)
    {
        res[i] = new CPUCryptoSystem::PlainText(negate_plaintext(*s[i]));
    }
    res.reshape(s.shape());
    return res;
}

inline Tensor<CPUCryptoSystem::CipherText *> CPUCryptoSystem::negate_ciphertext_tensor(const CPUCryptoSystem::PublicKey &pk, const Tensor<CPUCryptoSystem::CipherText *> &ct) const
{
    auto s = this->make_plaintext(-1);
    auto cts = ct;
    cts.flatten();
    Tensor<CPUCryptoSystem::CipherText *> res(ct.shape(), nullptr);
    res.flatten();
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
    BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI hr, pkr;
    hsm2k.power_of_h(hr, r);
    pk.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
#else
    Vector<BICYCL::Mpz> r_vec(cts.size());
    Vector<BICYCL::QFI> hr_vec(cts.size()), pkr_vec(cts.size());
    // see the comment in add_ciphertext_vectors
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < cts.size(); i++)
    {
        r_vec[i] = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
        hsm2k.power_of_h(hr_vec[i], r_vec[i]);
        pk.exponentiation(hsm2k, pkr_vec[i], r_vec[i]);
        if (hsm2k.compact_variant())
            hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr_vec[i]);
    }
#endif
#else
    (void)(pk);
#endif
    auto Cl_G = hsm2k.Cl_G();
    auto Cl_Delta = hsm2k.Cl_Delta();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < cts.num_elements(); i++)
    {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::QFI c1(hr), c2(pkr);
        Cl_G.nupow(c1, cts.at(i)->c1(), s);
        Cl_G.nucomp(c1, c1, hr);
        Cl_Delta.nupow(c2, cts.at(i)->c2(), s);
        Cl_Delta.nucomp(c2, c2, pkr);
#else
        BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
        Cl_G.nupow(c1, cts.at(i)->c1(), s);
        Cl_G.nucomp(c1, c1, hr_vec[i]);
        Cl_Delta.nupow(c2, cts.at(i)->c2(), s);
        Cl_Delta.nucomp(c2, c2, pkr_vec[i]);
#endif
#else
        BICYCL::QFI c1, c2;
        Cl_G.nupow(c1, cts.at(i)->c1(), s);
        Cl_Delta.nupow(c2, cts.at(i)->c2(), s);
#endif
        res.at(i) = new CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
    }
    res.reshape(ct.shape());
    return res;
}

inline Tensor<CPUCryptoSystem::CipherText *> CPUCryptoSystem::add_ciphertext_tensors(const PublicKey &pk_cpu, const Tensor<CPUCryptoSystem::CipherText *> &ct1_cpu_, const Tensor<CPUCryptoSystem::CipherText *> &ct2_cpu_) const
{
    if (ct1_cpu_.is_zero_degree() && ct2_cpu_.is_zero_degree())
    {
        return Tensor<CPUCryptoSystem::CipherText *>(new CPUCryptoSystem::CipherText(this->add_ciphertexts(pk_cpu, *ct1_cpu_.get_value(), *ct2_cpu_.get_value())));
    }
    if (ct1_cpu_.shape() != ct2_cpu_.shape())
    {
        throw std::invalid_argument("Tensor shapes must be equal");
    }
    auto ct1_cpu = ct1_cpu_, ct2_cpu = ct2_cpu_;
    auto res_shape = ct1_cpu.shape();
    ct1_cpu.flatten();
    ct2_cpu.flatten();
    Tensor<CPUCryptoSystem::CipherText *> res_vec({ct1_cpu.num_elements()}, nullptr);
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
    BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI hr, pkr;
    hsm2k.power_of_h(hr, r);
    pk_cpu.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
#else
    Vector<BICYCL::Mpz> r_vec(ct1.size());
    Vector<BICYCL::QFI> hr_vec(ct1.size()), pkr_vec(ct1.size());
    // Batch optimization can be done similiar to other nupow
    // port the precomputation version of nupow
    // Although do we need to do this?
    // As at this hierarchy, we can do parallelization
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct1.size(); i++)
    {
        r_vec[i] = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
        hsm2k.power_of_h(hr_vec[i], r_vec[i]);
        pk_cpu.exponentiation(hsm2k, pkr_vec[i], r_vec[i]);
        if (hsm2k.compact_variant())
            hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr_vec[i]);
    }
#endif
#else
    (void)(pk_cpu);
#endif
    auto Cl_G = hsm2k.Cl_G();
    auto Cl_Delta = hsm2k.Cl_Delta();
    auto num_elements = ct1_cpu.num_elements();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < num_elements; i++)
    {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::QFI c1(hr), c2(pkr);
        Cl_G.nucomp(c1, c1, ct1_cpu[i]->c1());
        Cl_G.nucomp(c1, c1, ct2_cpu[i]->c1());
        Cl_Delta.nucomp(c2, c2, ct1_cpu[i]->c2());
        Cl_Delta.nucomp(c2, c2, ct2_cpu[i]->c2());
#else
        BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
        Cl_G.nucomp(c1, c1, ct1_cpu[i]->c1());
        Cl_G.nucomp(c1, c1, ct2_cpu[i]->c1());
        Cl_Delta.nucomp(c2, c2, ct1_cpu[i]->c2());
        Cl_Delta.nucomp(c2, c2, ct2_cpu[i]->c2());
#endif
#else
        BICYCL::QFI c1, c2;
        Cl_G.nucomp(c1, ct1_cpu[i]->c1(), ct2_cpu[i]->c1());
        Cl_Delta.nucomp(c2, ct1_cpu[i]->c2(), ct2_cpu[i]->c2());
#endif
        res_vec[i] = new CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
    }
    res_vec.reshape(res_shape);
    return res_vec;
};

inline Tensor<CPUCryptoSystem::CipherText *> CPUCryptoSystem::scal_ciphertext_tensors(const CPUCryptoSystem::PublicKey &pk_cpu, const Tensor<CPUCryptoSystem::PlainText *> &s_cpu, const Tensor<CPUCryptoSystem::CipherText *> &cts) const
{
    if (s_cpu.ndim() > 2 || cts.ndim() > 2)
    {
        throw std::invalid_argument("Tensors must be 0D, 1D or 2D for now");
    }
    if (s_cpu.is_zero_degree() && cts.is_zero_degree())
    {
        return Tensor<CPUCryptoSystem::CipherText *>(new CPUCryptoSystem::CipherText(this->scal_ciphertext(pk_cpu, *s_cpu.get_value(), *cts.get_value())));
    }

    if (s_cpu.is_column_vector() && cts.is_column_vector())
    {
        if (s_cpu.shape()[0] != cts.shape()[0])
        {
            throw std::invalid_argument("Vector sizes must be equal");
        }
        Tensor<CPUCryptoSystem::CipherText *> res_vec(cts.shape(), nullptr);
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
        BICYCL::QFI hr, pkr;
        hsm2k.power_of_h(hr, r);
        pk_cpu.exponentiation(hsm2k, pkr, r);
        if (hsm2k.compact_variant())
            hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
#else
        Vector<BICYCL::Mpz> r_vec(cts.size());
        Vector<BICYCL::QFI> hr_vec(cts.size()), pkr_vec(cts.size());
        // Batch optimization can be done similiar to other nupow
        // port the precomputation version of nupow
        // Although do we need to do this?
        // As at this hierarchy, we can do parallelization
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < cts.size(); i++)
        {
            r_vec[i] = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
            hsm2k.power_of_h(hr_vec[i], r_vec[i]);
            pk_cpu.exponentiation(hsm2k, pkr_vec[i], r_vec[i]);
            if (hsm2k.compact_variant())
                hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr_vec[i]);
        }
#endif
#else
        (void)(pk_cpu);
#endif
        auto Cl_G = hsm2k.Cl_G();
        auto Cl_Delta = hsm2k.Cl_Delta();
        CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < cts.size(); i++)
        {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
            BICYCL::QFI c1(hr), c2(pkr);
            Cl_G.nupow(c1, cts.at(i)->c1(), *s_cpu[i]);
            Cl_G.nucomp(c1, c1, hr);
            Cl_Delta.nupow(c2, cts.at(i)->c2(), *s_cpu[i]);
            Cl_Delta.nucomp(c2, c2, pkr);
#else
            BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
            Cl_G.nupow(c1, cts.at(i)->c1(), *s_cpu[i]);
            Cl_G.nucomp(c1, c1, hr_vec[i]);
            Cl_Delta.nupow(c2, cts.at(i)->c2(), *s_cpu[i]);
            Cl_Delta.nucomp(c2, c2, pkr_vec[i]);
#endif
#else
            BICYCL::QFI c1, c2;
            Cl_G.nupow(c1, cts.at(i)->c1(), *s_cpu[i]);
            Cl_Delta.nupow(c2, cts.at(i)->c2(), *s_cpu[i]);
#endif
            res_vec.at(i)= new CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
        }
        return res_vec;
    }

    if (s_cpu.ndim() > 2 || cts.ndim() > 2)
    {
        throw std::invalid_argument("Tensors must be 0D, 1D or 2D for now");
    }
    auto s_cpu_flattened = s_cpu;
    auto cts_flattened = cts;
    s_cpu_flattened.flatten();
    cts_flattened.flatten();
    Tensor<CPUCryptoSystem::CipherText *> res_mat({cts.shape()[0], s_cpu.shape()[1]}, nullptr);
    res_mat.flatten();
    CPUCryptoSystem::CipherText zero = this->encrypt(pk_cpu, this->make_plaintext(0));
    for (size_t i = 0; i < res_mat.num_elements(); i++)
    {
        res_mat[i] = new CPUCryptoSystem::CipherText(zero);
    }
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
    BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI hr, pkr;
    hsm2k.power_of_h(hr, r);
    pk_cpu.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
#else
    Vector<BICYCL::Mpz> r_vec(ct1.num_elements());
    Vector<BICYCL::QFI> hr_vec(ct1.num_elements()), pkr_vec(ct1.num_elements());
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < ct1.num_elements(); i++)
    {
        r_vec[i] = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
        hsm2k.power_of_h(hr_vec[i], r_vec[i]);
        pk_cpu.exponentiation(hsm2k, pkr_vec[i], r_vec[i]);
        if (hsm2k.compact_variant())
            hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr_vec[i]);
    }
#endif
#else
    (void)(pk_cpu);
#endif
    auto Cl_G = hsm2k.Cl_G();
    auto Cl_Delta = hsm2k.Cl_Delta();
    size_t n = cts.shape()[0], m = cts.shape()[1], p = s_cpu.shape()[1];
    BICYCL::Mpz **s_vec = new BICYCL::Mpz *[m * p];
    // to make sure tensor is contiguous
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0; i < m; i++)
    {
        for (size_t j = 0; j < p; j++)
        {
            s_vec[i * p + j] = new BICYCL::Mpz(*s_cpu_flattened.at(i * p + j));
        }
    }
    BICYCL::QFI **c1_nupows_arr = new BICYCL::QFI *[n * m * p];
    BICYCL::QFI **c2_nupows_arr = new BICYCL::QFI *[n * m * p];
    auto cl_g_bound = Cl_G.default_nucomp_bound();
    auto cl_delta_bound = Cl_Delta.default_nucomp_bound();
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0; i < n; i++) for (size_t j = 0; j < m; j++)
    {
        {
            qfi_nupow(c1_nupows_arr + i * m * p + j * p, cts_flattened.at(i * m + j)->c1(), s_vec + j * p, p, cl_g_bound);
            qfi_nupow(c2_nupows_arr + i * m * p + j * p, cts_flattened.at(i * m + j)->c2(), s_vec + j * p, p, cl_delta_bound);
        }
    }
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0; i < n; i++)
    {
        for (size_t k = 0; k < p; k++)
        {
            for (size_t j = 0; j < m; j++)
            {
                Cl_G.nucomp(res_mat.at(i * p + k)->c1(),
                            res_mat.at(i * p + k)->c1(),
                            *(c1_nupows_arr[i * m * p + j * p + k]));
                Cl_Delta.nucomp(res_mat.at(i * p + k)->c2(),
                                res_mat.at(i * p + k)->c2(),
                                *(c2_nupows_arr[i * m * p + j * p + k]));
            }
        }
    }
    for (size_t i = 0; i < m * p; i++)
    {
        delete s_vec[i];
    }
    delete[] s_vec;
    for (size_t i = 0; i < n * m * p; i++)
    {
        delete c1_nupows_arr[i];
        delete c2_nupows_arr[i];
    }
    delete[] c1_nupows_arr;
    delete[] c2_nupows_arr;

#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0; i < n; i++)
    {
        for (size_t k = 0; k < p; k++)
        {
            Cl_G().nucomp(res_mat[i * p + k]->c1(),
                          res_mat[i * p + k]->c1(),
                          hr);
            Cl_G().nucomp(res_mat[i * p + k]->c2(),
                          res_mat[i * p + k]->c2(),
                          pkr);
        }
    };
#else
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE_COLLAPSE_2 for (size_t i = 0; i < n; i++)
    {
        for (size_t k = 0; k < p; k++)
        {
            Cl_G().nucomp(res_mat[i * p + k]->c1(),
                          res_mat[i * p + k]->c1(),
                          hr_vec[i]);
            Cl_G().nucomp(res_mat[i * p + k]->c2(),
                          res_mat[i * p + k]->c2(),
                          pkr_vec[i]);
        }
    };
#endif
#endif
    res_mat.reshape({n, p});
    return res_mat;
}
