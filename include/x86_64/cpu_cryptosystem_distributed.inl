template <typename T>
using Array = std::vector<T>;

template <typename T>
using Matrix = Vector<Vector<T>>;

struct AccessStructure
{
    int t;
    int n;
    AccessStructure(int t = 0, int n = 0) : t(t), n(n) {}
};

typedef struct
{
    Matrix<int> M;
    Matrix<int> Sie;
    int rows;
    int cols;
} ISP;

Matrix<int> compute_M_OR(const Matrix<int> &Ma, const Matrix<int> &Mb)
{
    int da = Ma.size();
    int ea = Ma[0].size();
    int db = Mb.size();
    int eb = Mb[0].size();

    int M_OR_rows = da + db;
    int M_OR_cols = ea + eb - 1;

    Matrix<int> M_OR(M_OR_rows, Vector<int>(M_OR_cols, 0));

    // Fill in the first column with concatenated c(a) and c(b)
    for (int i = 0; i < da; ++i)
    {
        M_OR[i][0] = Ma[i][0];
    }
    for (int i = 0; i < db; ++i)
    {
        M_OR[da + i][0] = Mb[i][0];
    }

    // Fill the remaining columns for Ma with db trailing zeros
    for (int i = 0; i < da; ++i)
    {
        for (int j = 1; j < ea; ++j)
        {
            M_OR[i][j] = Ma[i][j];
        }
    }

    // Fill the remaining columns for Mb with da leading zeros
    for (int i = 0; i < db; ++i)
    {
        for (int j = 1; j < eb; ++j)
        {
            M_OR[da + i][ea + j - 1] = Mb[i][j];
        }
    }

    return M_OR;
}

Matrix<int> compute_M_AND(const Matrix<int> &Ma, const Matrix<int> &Mb)
{
    int da = Ma.size();
    int ea = Ma[0].size();
    int db = Mb.size();
    int eb = Mb[0].size();

    int M_AND_rows = da + db;
    int M_AND_cols = ea + eb;

    Matrix<int> M_AND(M_AND_rows, Vector<int>(M_AND_cols, 0));

    // Fill in the first column with c(a) following db zeros & second column with
    // c(a) concatenated c(b)
    for (int i = 0; i < da; ++i)
    {
        M_AND[i][0] = Ma[i][0];
        M_AND[i][1] = Ma[i][0];
    }
    for (int i = 0; i < db; ++i)
    {
        M_AND[da + i][1] = Mb[i][0];
    }

    // Fill the remaining columns for Ma with db trailing zeros
    for (int i = 0; i < da; ++i)
    {
        for (int j = 1; j < ea; ++j)
        {
            M_AND[i][j + 1] = Ma[i][j];
        }
    }

    // Fill the remaining columns for Mb with da leading zeros
    for (int i = 0; i < db; ++i)
    {
        for (int j = 1; j < eb; ++j)
        {
            M_AND[da + i][ea + j] = Mb[i][j];
        }
    }

    return M_AND;
}

Matrix<int> generate_distribution_matrix_M(int n, int t,
                                           int threshold_combinations)
{
    // See https://cs.au.dk/fileadmin/site_files/cs/PhD/PhD_Dissertations__pdf/Thesis-RIT.pdf
    // Section 3.3.1 : Page 24,25,26
    Matrix<int> Mu{{1}};
    Matrix<int> Mt = Mu;

    for (int i = 1; i < t; i++)
    {
        Mt = compute_M_AND(Mt, Mu);
    }

    Matrix<int> M = Mt;
    for (int i = 1; i < threshold_combinations; i++)
    {
        M = compute_M_OR(M, Mt);
    }
    return M;
}

ISP generate_isp(const AccessStructure &A)
{
    int n = A.n, t = A.t;
    int threshold_combinations = nCr(n, t);
    Matrix<int> M = generate_distribution_matrix_M(n, t, threshold_combinations);

    // Create the mapping between the rows of M and the threshold combinations of parties (parties are represented by numbers staring from 0)
    // ith row of Sie contains the row indexes of M corresponding to ith threshold combination of parties when sorted
    Matrix<int> Sie(threshold_combinations, Array<int>(t, 0));
    int M_row_num = 0;
    for (int i = 0; i < threshold_combinations; i++)
    {
        for (int j = 0; j < t; j++)
        {
            Sie[i][j] = M_row_num++;
        }
    }

    ISP isp;
    isp.M = M;
    isp.Sie = Sie;
    isp.rows = M.size();
    isp.cols = M[0].size();

    return isp;
}

// Function to compute rho: ρ := (secret, ρ2, . . . , ρe)⊤; (ρ2, . . . , ρe) ←− [2^(l0+λ), 2^(l0+λ)]^(e−1)
Array<BICYCL::Mpz> compute_rho(const BICYCL::Mpz &secret, int e, const BICYCL::CL_HSM2k &hsm2k, BICYCL::RandGen &randgen)
{
    Array<BICYCL::Mpz> rho(e);
    rho[0] = secret; // Set ρ(0) = s as per the algorithm
    for (int i = 1; i < e; i++)
    {
        rho[i] = randgen.random_mpz(
            hsm2k.encrypt_randomness_bound()); // This should be random value in
                                               // range [-2^(l0+λ), 2^(l0+λ)]^(e−1)
    }
    return rho;
}

Matrix<BICYCL::Mpz> compute_shares(const ISP &isp, const Array<BICYCL::Mpz> &rho)
{
    // See https://eprint.iacr.org/2022/1143.pdf Algorithm 8
    Matrix<int> M = isp.M;
    Matrix<int> Sie = isp.Sie;
    int rows = isp.rows, cols = isp.cols;

    // Shares are computed for each party as per mapping
    // Shares are stored in the same way as Sie.
    // ith row of shares matrix contains shares of parties corresponding to ith threshold combination of parties when sorted
    Matrix<BICYCL::Mpz> shares;
    for (auto Sp : Sie)
    {
        Array<BICYCL::Mpz> si;
        for (int i : Sp)
        {
            BICYCL::Mpz sij(BICYCL::Mpz((unsigned long)(0)));
            if (i != -1)
            {
                for (int j = 0; j < cols; j++)
                {
                    BICYCL::Mpz mult;
                    sij.mul(mult, rho[j], BICYCL::Mpz((unsigned long)(M[i][j])));
                    sij.add(sij, sij, mult);
                }
            }
            si.push_back(sij);
        }
        shares.push_back(si);
    }
    return shares;
}

Matrix<BICYCL::Mpz> get_shares(const BICYCL::CL_HSM2k &hsm2k,
                                BICYCL::RandGen &randgen, const ISP &isp,
                               const BICYCL::Mpz& secret)
{
    Array<BICYCL::Mpz> rho = compute_rho(secret, isp.cols, hsm2k, randgen);
    return compute_shares(isp, rho);
}

// Function to compute λ for one threshold combination
Array<BICYCL::Mpz> compute_lambda(int t)
{
    // See https://cs.au.dk/fileadmin/site_files/cs/PhD/PhD_Dissertations__pdf/Thesis-RIT.pdf
    // Lemma 3.2, Page 26,27

    // One threshold combination contains each party once with just & operator between them
    // Ex, consider t = 4, threshold combination = x1 & x2 & x3 & x4
    // From the Lemma 3.2 of above mentioned doc, lambda(f1 & f2) = [...lambda(f1), -(...lambda(f2))]
    // Also, lambda(xi) = [1], So, lambda(x1 & x2) = [1, -1], lambda((x1 & x2) & x3) = [1, -1, -1] and so on.
    Array<BICYCL::Mpz> lambda{BICYCL::Mpz((unsigned long)(1))};
    for (int i = 0; i < t; i++)
    {
        lambda.push_back(BICYCL::Mpz((long)(-1)));
    }
    return lambda;
}

BICYCL::QFI compute_d(const BICYCL::CL_HSM2k &hsm2k, const Array<BICYCL::QFI> &ds,
                      const Array<BICYCL::Mpz> &lambda)
{
    BICYCL::QFI d;
    for (int i = 0; i < ds.size(); i++)
    {
        BICYCL::QFI r;
        hsm2k.Cl_G().nupow(r, ds[i], lambda[i]);
        hsm2k.Cl_G().nucomp(d, d, r);
    }
    return d;
}

BICYCL::QFI partDecrypt(const BICYCL::CL_HSM2k &hsm2k,
                        const BICYCL::CL_HSM2k::CipherText &ct, const BICYCL::Mpz &ski)
{
    // See https://eprint.iacr.org/2022/1143.pdf Algorithm 10
    BICYCL::QFI di;
    hsm2k.Cl_G().nupow(di, ct.c1(), ski); // di = c1^sj
    if (hsm2k.compact_variant())
        hsm2k.from_Cl_DeltaK_to_Cl_Delta(di);

    return di;
}

BICYCL::CL_HSM2k::ClearText finalDecrypt(const BICYCL::CL_HSM2k &hsm2k,
                                         const BICYCL::CL_HSM2k::CipherText &ct,
                                         const Array<BICYCL::QFI> &ds)
{
    // See https://eprint.iacr.org/2022/1143.pdf Algorithm 11

    Array<BICYCL::Mpz> lambda = compute_lambda(ds.size());

    BICYCL::QFI d = compute_d(hsm2k, ds, lambda);

    BICYCL::QFI r;
    hsm2k.Cl_Delta().nucompinv(r, ct.c2(), d); /* c2 . d^-1 */

    return BICYCL::CL_HSM2k::ClearText(hsm2k, hsm2k.dlog_in_F(r));
}

Vector<size_t> get_next_lexio_combination(Vector<size_t> &current_combination, int n, int t)
{
    Vector<size_t> next_combination = current_combination;
    int j = t - 1;
    while (j >= 0 && next_combination[j] == n - t + j)
    {
        j--;
    }
    if (j >= 0)
    {
        next_combination[j]++;
        for (int k = j + 1; k < t; k++)
        {
            next_combination[k] = next_combination[j] + k - j;
        }
    }
    return next_combination;
}

inline Vector<Vector<CPUCryptoSystem::SecretKeyShare>> CPUCryptoSystem::keygen(const CPUCryptoSystem::SecretKey& sk,  size_t threshold,size_t num_parties) const
{
    auto isp = generate_isp(AccessStructure(threshold, num_parties));
    auto shares = get_shares(hsm2k, rand_gen, isp, sk);
    // contains shares of each party for each threshold combination
    Vector<Vector<CPUCryptoSystem::SecretKeyShare>> secret_key_shares(num_parties);
    Vector<size_t> current_threshold_combination(num_parties, 0);
    for (size_t i = 0; i < num_parties; i++)
        current_threshold_combination[i] = i;
    for (size_t i = 0; i < nCr(num_parties, threshold); i++)
    {
        for (size_t j = 0; j < threshold; j++)
        {
            secret_key_shares[current_threshold_combination[j]].push_back(shares[i][j]);
        }
        current_threshold_combination = get_next_lexio_combination(current_threshold_combination, num_parties, threshold);
    }
    return secret_key_shares;
}

inline CPUCryptoSystem::PartDecryptionResult CPUCryptoSystem::part_decrypt(const CPUCryptoSystem::SecretKeyShare &sks, const CPUCryptoSystem::CipherText &ct) const
{
    return partDecrypt(hsm2k, ct, sks);
}

inline CPUCryptoSystem::PlainText CPUCryptoSystem::combine_part_decryption_results(const CPUCryptoSystem::CipherText &ct, const Vector<CPUCryptoSystem::PartDecryptionResult> &pdrs) const
{
    return this->to_mpz(finalDecrypt(hsm2k, ct, pdrs));
}
