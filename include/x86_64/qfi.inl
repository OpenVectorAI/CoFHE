inline void qfi_nupow(BICYCL::QFI **r_, const BICYCL::QFI &f, BICYCL::Mpz **n_, size_t count,
                      const BICYCL::Mpz &L)
{
    if (count == 0)
        return;

    for (size_t i = 0; i < count; i++)
    {
        r_[i] = new BICYCL::QFI();
    }

    BICYCL::QFI::OpsAuxVars tmp;

    /* implem of wNAF*: a left to right wNAF (see Brian King, ACNS 2008) */
    const mp_limb_t w = 7;
    const mp_limb_t pow2w = (1UL << w);
    const mp_limb_t u = (1UL << (w - 2));

    /* precomputation: tab[i] = f^(2*i+1)  for 0 <= i < u = 2^(w-2) */
    BICYCL::QFI ff(f);
    BICYCL::QFI tab[u];

    BICYCL::QFI::nudupl(ff, f, L, tmp);
    tab[0] = f;
    for (mp_limb_t i = 1; i < u; i++)
        BICYCL::QFI::nucomp(tab[i], tab[i - 1], ff, L, 0, tmp); /* tab[i] <- tab[i-1]*ff */
    auto tab_end = std::chrono::high_resolution_clock::now();
    std::unordered_map<size_t, BICYCL::QFI> cache;

    auto get_doubled = [&](BICYCL::QFI &r, size_t &curr_degree, size_t doubling_degree,
                           const BICYCL::Mpz &L, BICYCL::QFI::OpsAuxVars &tmp) -> void
    {
        size_t final_degree = (1 << doubling_degree) * curr_degree;
        if (cache.find(curr_degree) == cache.end())
            cache[curr_degree] = BICYCL::QFI(r);
        if (cache.find(final_degree) != cache.end())
        {
            curr_degree = final_degree;
            r = BICYCL::QFI(cache[final_degree]);
        }
        else
        {
            size_t already_doubled_degree = 0;
            // size_t intermediate_degree = final_degree/2;
            // for (size_t i = doubling_degree-1;i>0; --i) {
            //     if (cache.find(intermediate_degree) != cache.end()) {
            //         r = QFI(cache[intermediate_degree]);
            //         curr_degree = intermediate_degree;
            //         already_doubled_degree = i;
            //         break;
            //     }
            //     intermediate_degree/=2;
            // }

            for (size_t i = 1; i <= doubling_degree - already_doubled_degree; i++)
            {
                BICYCL::QFI::nudupl(r, r, L, tmp);
                cache[curr_degree * 2] = BICYCL::QFI(r);
                curr_degree *= 2;
            }
        }
    };

    for (size_t exp_idx = 0; exp_idx < count; exp_idx++)
    {
        BICYCL::Mpz &n = *n_[exp_idx];
        BICYCL::QFI &r = *r_[exp_idx];
        size_t curr_degree = 0;

        int j = n.nbits() - 1;
        mp_limb_t c;

        {
            /* for the first digit we know that dj=1 and c=0 */
            mp_limb_t m = n.extract_bits((size_t)j, w);
            c = m & 0x1;                    /* d_{j-w+1} */
            mp_limb_t t = m + (m & 0x1);    /* + d_{j-w+1} */
            size_t val2 = mpn_scan1(&t, 0); /* note: m cannot be zero */
            size_t tau = val2 < w ? val2 : w - 1;
            t >>= tau;

            r = t == 2 ? ff : tab[t >> 1];
            curr_degree = t == 2 ? 2 : ((t >> 1) * 2 + 1);
            size_t b = ((size_t)j) < w - 1 ? tau + 1 + j - w : tau;
            get_doubled(r, curr_degree, b, L, tmp);
            j -= w;
        }

        while (j >= 0)
        {
            mp_limb_t m = n.extract_bits((size_t)j, w);
            mp_limb_t dj = (m >> (w - 1)) & 0x1;
            mp_limb_t djmwp1 = m & 0x1;

            if (c == dj)
            {
                get_doubled(r, curr_degree, 1, L, tmp);
                j -= 1;
            }
            else
            {
                int neg = c;
                mp_limb_t t = m + djmwp1;
                t = c ? (pow2w - t) : t;
                c = djmwp1;

                size_t val2 = t > 0 ? mpn_scan1(&t, 0) : w - 1;
                size_t tau = val2 < w ? val2 : w - 1;
                t >>= tau;
                get_doubled(r, curr_degree, (w - tau), L, tmp);
                BICYCL::QFI::nucomp(r, r, t == 2 ? ff : tab[t >> 1], L, neg, tmp);
                if (neg)
                {
                    curr_degree -= ((t == 2) ? 2 : ((t >> 1) * 2 + 1));
                }
                else
                {
                    curr_degree += ((t == 2) ? 2 : ((t >> 1) * 2 + 1));
                }
                size_t b = ((size_t)j) < w - 1 ? tau + 1 + j - w : tau;
                get_doubled(r, curr_degree, b, L, tmp);
                j -= w;
            }
        }

        if (c)
            BICYCL::QFI::nucomp(r, r, tab[0], L, 1, tmp);
        curr_degree += 1;

        if (n.sgn() < 0)
        {
            r.neg();
        }
    }
}
