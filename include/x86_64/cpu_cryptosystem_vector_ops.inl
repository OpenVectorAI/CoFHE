// #define ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS 1
// #define DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION 1

inline Vector<CPUCryptoSystem::CipherText *> CPUCryptoSystem::encrypt_vector(const CPUCryptoSystem::PublicKey &pk, const Vector<CPUCryptoSystem::PlainText*> &pts) const
{
    Vector<CPUCryptoSystem::CipherText *> res_vec(pts.size());
    BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI c1, pkr;
    hsm2k.power_of_h(c1, r);
    pk.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < pts.size(); i++)
    {
        res_vec[i] = new CPUCryptoSystem::CipherText{hsm2k, this->to_plaintext(*pts[i]), c1, pkr};
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::PlainText *> CPUCryptoSystem::decrypt_vector(const CPUCryptoSystem::SecretKey &sk, const Vector<CPUCryptoSystem::CipherText *> &cts) const
{
    Vector<CPUCryptoSystem::PlainText *> res_vec(cts.size());
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < cts.size(); i++)
    {
        res_vec[i] = new CPUCryptoSystem::PlainText{this->to_mpz(hsm2k.decrypt(sk, *cts[i]))};
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::PartDecryptionResult *> CPUCryptoSystem::part_decrypt_vector(const CPUCryptoSystem::SecretKeyShare &sks, const Vector<CPUCryptoSystem::CipherText *> &cts) const
{
    Vector<CPUCryptoSystem::PartDecryptionResult *> res_vec(cts.size());
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < cts.size(); i++)
    {
        res_vec[i] = new CPUCryptoSystem::PartDecryptionResult{part_decrypt(sks, *cts[i])};
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::PlainText *> CPUCryptoSystem::combine_part_decryption_results_vector(const CPUCryptoSystem::CipherText &ct, const Vector<CPUCryptoSystem::PartDecryptionResult *> &pdrs) const
{
    Vector<CPUCryptoSystem::PlainText *> res_vec(pdrs.size());
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < pdrs.size(); i++)
    {
        Vector<CPUCryptoSystem::PartDecryptionResult> pdrs_vec{pdrs.size()};
        for (size_t j = 0; j < pdrs.size(); j++)
        {
            pdrs_vec[j] = *pdrs[j];
        }
        res_vec[i] = new CPUCryptoSystem::PlainText{combine_part_decryption_results(ct, pdrs_vec)};
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::CipherText *> CPUCryptoSystem::add_ciphertext_vectors(const CPUCryptoSystem::PublicKey &pk, const Vector<CPUCryptoSystem::CipherText *> &ct1, const Vector<CPUCryptoSystem::CipherText *> &ct2) const
{
    if (ct1.size() != ct2.size())
    {
        throw std::invalid_argument("Vector sizes must be equal");
    }
    Vector<CPUCryptoSystem::CipherText *> res_vec(ct1.size());
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
    BICYCL::Mpz r = rand_gen.random_mpz(hsm2k.encrypt_randomness_bound());
    BICYCL::QFI hr, pkr;
    hsm2k.power_of_h(hr, r);
    pk.exponentiation(hsm2k, pkr, r);
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(pkr);
#else
    Vector<BICYCL::Mpz> r_vec(ct1.size());
    Vector<BICYCL::QFI> hr_vec(ct1.size()), pkr_vec(ct1.size());
    // Batch optimization can be done similiar to other nupow
    // port the precomputation version of nupow
    // Although do we need to do this?
    // As at this hierarchy, we can do parallelization
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE
    for (size_t i = 0; i < ct1.size(); i++)
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
    for (size_t i = 0; i < ct1.size(); i++)
    {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::QFI c1(hr), c2(pkr);
        Cl_G.nucomp(c1, c1, ct1[i]->c1());
        Cl_G.nucomp(c1, c1, ct2[i]->c1());
        Cl_Delta.nucomp(c2, c2, ct1[i]->c2());
        Cl_Delta.nucomp(c2, c2, ct2[i]->c2());
#else
        BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
        Cl_G.nucomp(c1, c1, ct1[i]->c1());
        Cl_G.nucomp(c1, c1, ct2[i]->c1());
        Cl_Delta.nucomp(c2, c2, ct1[i]->c2());
        Cl_Delta.nucomp(c2, c2, ct2[i]->c2());
#endif
#else
        BICYCL::QFI c1, c2;
        Cl_G.nucomp(c1, ct1[i]->c1(), ct2[i]->c1());
        Cl_Delta.nucomp(c2, ct1[i]->c2(), ct2[i]->c2());
#endif
        res_vec[i] = new CPUCryptoSystem::CipherText{std::move(c1), std::move(c2)};
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::CipherText *> CPUCryptoSystem::scal_ciphertext_vector(const CPUCryptoSystem::PublicKey &pk, const CPUCryptoSystem::PlainText &s, const Vector<CPUCryptoSystem::CipherText *> &cts) const
{
    if (s.sgn() < 0)
    {
        throw std::invalid_argument("CPUCryptoSystem::PlainText must be non-negative");
    }
    Vector<CPUCryptoSystem::CipherText *> res_vec(cts.size());
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
    for (size_t i = 0; i < cts.size(); i++)
    {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::QFI c1(hr), c2(pkr);
        Cl_G.nupow(c1, cts[i]->c1(), s);
        Cl_G.nucomp(c1, c1, hr);
        Cl_Delta.nupow(c2, cts[i]->c2(), s);
        Cl_Delta.nucomp(c2, c2, pkr);
#else
        BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
        Cl_G.nupow(c1, cts[i]->c1(), s);
        Cl_G.nucomp(c1, c1, hr_vec[i]);
        Cl_Delta.nupow(c2, cts[i]->c2(), s);
        Cl_Delta.nucomp(c2, c2, pkr_vec[i]);
#endif
#else
        BICYCL::QFI c1, c2;
        Cl_G.nupow(c1, cts[i]->c1(), s);
        Cl_Delta.nupow(c2, cts[i]->c2(), s);
#endif
        res_vec[i] = new CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
    }
    return res_vec;
}

inline Vector<CPUCryptoSystem::CipherText *> CPUCryptoSystem::scal_ciphertext_vector(const CPUCryptoSystem::PublicKey &pk, const Vector<CPUCryptoSystem::PlainText *> &s_cpu, const Vector<CPUCryptoSystem::CipherText *> &cts) const
{
    if (s_cpu.size() != cts.size())
    {
        throw std::invalid_argument("Vector sizes must be equal");
    }
    Vector<CPUCryptoSystem::CipherText *> res_vec(cts.size());
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
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < cts.size(); i++)
    {
#ifdef ADD_RANDOMNESS_IN_HOMOMORPHIC_OPERATIONS
#ifndef DIFFERENT_RANDOMNESS_FOR_EACH_OPERATION
        BICYCL::QFI c1(hr), c2(pkr);
        Cl_G.nupow(c1, cts[i]->c1(), *s_cpu[i]);
        Cl_G.nucomp(c1, c1, hr);
        Cl_Delta.nupow(c2, cts[i]->c2(), *s_cpu[i]);
        Cl_Delta.nucomp(c2, c2, pkr);
#else
        BICYCL::QFI c1(hr_vec[i]), c2(pkr_vec[i]);
        Cl_G.nupow(c1, cts[i]->c1(), *s_cpu[i]);
        Cl_G.nucomp(c1, c1, hr_vec[i]);
        Cl_Delta.nupow(c2, cts[i]->c2(), *s_cpu[i]);
        Cl_Delta.nucomp(c2, c2, pkr_vec[i]);
#endif
#else
        BICYCL::QFI c1, c2;
        Cl_G.nupow(c1, cts[i]->c1(), *s_cpu[i]);
        Cl_Delta.nupow(c2, cts[i]->c2(), *s_cpu[i]);
#endif
        res_vec[i] = new CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
    }
    return res_vec;
}
