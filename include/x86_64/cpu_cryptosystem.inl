inline CPUCryptoSystem::SecretKey CPUCryptoSystem::keygen() const {
    return hsm2k.keygen(rand_gen);
}

inline CPUCryptoSystem::PublicKey
CPUCryptoSystem::keygen(const CPUCryptoSystem::SecretKey& sk) const {
    return hsm2k.keygen(sk);
}

inline CPUCryptoSystem::CipherText
CPUCryptoSystem::encrypt(const CPUCryptoSystem::PublicKey& pk,
                         const CPUCryptoSystem::PlainText& pt) const {
    return hsm2k.encrypt(pk, this->to_plaintext(pt), rand_gen);
}

inline CPUCryptoSystem::PlainText
CPUCryptoSystem::decrypt(const CPUCryptoSystem::SecretKey& sk,
                         const CPUCryptoSystem::CipherText& ct) const {
    return this->to_mpz(hsm2k.decrypt(sk, ct));
}

inline CPUCryptoSystem::CipherText
CPUCryptoSystem::add_ciphertexts(const CPUCryptoSystem::PublicKey& pk,
                                 const CPUCryptoSystem::CipherText& ct1,
                                 const CPUCryptoSystem::CipherText& ct2) const {
    return hsm2k.add_ciphertexts(pk, ct1, ct2, rand_gen);
}

inline CPUCryptoSystem::CipherText
CPUCryptoSystem::scal_ciphertext(const CPUCryptoSystem::PublicKey& pk,
                                 const CPUCryptoSystem::PlainText& s,
                                 const CPUCryptoSystem::CipherText& ct) const {
    return hsm2k.scal_ciphertexts(pk, ct, s, rand_gen);
}

inline CPUCryptoSystem::PlainText CPUCryptoSystem::generate_random_plaintext(
    const CPUCryptoSystem::PlainText& min_bound,
    const CPUCryptoSystem::PlainText& max_bound) const {
    BICYCL::Mpz res, diff;
    BICYCL::Mpz::sub(diff, max_bound, min_bound);
    BICYCL::Mpz::add(res, min_bound, rand_gen.random_mpz(diff));
    return res;
}

inline BICYCL::Mpz map_to_positive(float x, const mpf_t& scaling_factor,
                                   const mpf_t& M, const mpf_t& mM_half) {
    mpf_t scaled_x;
    mpf_init(scaled_x);
    mpf_set_d(scaled_x, x);
    mpf_mul(scaled_x, scaled_x, scaling_factor);
    if (x < 0) {
        mpf_add(scaled_x, scaled_x, M);
    }
    mpz_t scaled_x_z;
    mpz_init(scaled_x_z);
    mpz_set_f(scaled_x_z, scaled_x);
    std::string scaled_x_str = mpz_get_str(NULL, 10, scaled_x_z);
    mpz_clear(scaled_x_z);
    mpf_clear(scaled_x);
    return BICYCL::Mpz(scaled_x_str);
}

inline float map_back(const BICYCL::Mpz& z, const mpf_t& cscaling_factor,
                      const mpf_t& M, const mpf_t& mM_half,
                      unsigned int escaling_factor = 1,
                      unsigned int depth = 1) {
    mpf_t num, scaling_factor;
    mpf_init(num);
    mpf_init(scaling_factor);
    mpf_set_z(num, z.operator const __mpz_struct*());
    mpf_set_d(scaling_factor, escaling_factor);
    mpf_pow_ui(scaling_factor, scaling_factor, depth);
    mpf_mul(scaling_factor, scaling_factor, cscaling_factor);
    if (mpf_cmp(num, mM_half) < 0) {
        mpf_div(num, num, scaling_factor);
    } else {
        mpf_sub(num, num, M);
        mpf_div(num, num, scaling_factor);
    }
    float res = mpf_get_d(num);
    mpf_clear(num);
    return res;
}

inline CPUCryptoSystem::PlainText
CPUCryptoSystem::negate_plaintext(const CPUCryptoSystem::PlainText& s) const {
    float x = map_back(s, scaling_factor, mM, mM_half);
    return map_to_positive(-x, scaling_factor, mM, mM_half);
}

inline CPUCryptoSystem::CipherText CPUCryptoSystem::negate_ciphertext(
    const CPUCryptoSystem::PublicKey& pk,
    const CPUCryptoSystem::CipherText& ct) const {
    return hsm2k.scal_ciphertexts(pk, ct, this->make_plaintext(-1), rand_gen);
}

inline CPUCryptoSystem::PlainText
CPUCryptoSystem::add_plaintexts(const CPUCryptoSystem::PlainText& pt1,
                                const CPUCryptoSystem::PlainText& pt2) const {
    BICYCL::Mpz s;
    BICYCL::Mpz::add(s, pt1, pt2);
    BICYCL::Mpz::mod(s, s, hsm2k.cleartext_bound());
    return s;
}

inline CPUCryptoSystem::PlainText CPUCryptoSystem::multiply_plaintexts(
    const CPUCryptoSystem::PlainText& pt1,
    const CPUCryptoSystem::PlainText& pt2) const {
    BICYCL::Mpz s;
    BICYCL::Mpz::mul(s, pt1, pt2);
    BICYCL::Mpz::mod(s, s, hsm2k.cleartext_bound());
    return s;
}

inline CPUCryptoSystem::PlainText
CPUCryptoSystem::make_plaintext(float value) const {
    return map_to_positive(value, scaling_factor, mM, mM_half);
}

inline float
CPUCryptoSystem::get_float_from_plaintext(const CPUCryptoSystem::PlainText& pt,
                                          unsigned int scaling_factor,
                                          unsigned int depth) const {
    return map_back(pt, this->scaling_factor, mM, mM_half, scaling_factor,
                    depth);
}

inline String CPUCryptoSystem::serialize() const {
    return "CPUCryptoSystem " + std::to_string(sec_level) + " " +
           std::to_string(hsm2k.k()) + " " +
           std::to_string(hsm2k.compact_variant());
}

inline CPUCryptoSystem CPUCryptoSystem::deserialize(const String& data) {
    std::istringstream ss{data};
    String type;
    int sec_level, k;
    bool compact_variant;
    ss >> type >> sec_level >> k >> compact_variant;
    return CPUCryptoSystem(sec_level, k, compact_variant);
}

inline std::string serialize_bicycl_mpz_binary(const BICYCL::Mpz& mpz) {
    // first byte represents the sign
    uint32_t num_bytes = (static_cast<uint32_t>(
        (mpz_sizeinbase(static_cast<mpz_srcptr>(mpz), 2) + 7) / 8));

    std::string ss(num_bytes + 1, 0);
    char* data_ptr = ss.data();
    // write the sign
    char sign = mpz.sgn() == 1 ? 0 : 1;
    memcpy(data_ptr, &sign, sizeof(char));
    data_ptr += sizeof(char);
    // write the data
    mpz_export(data_ptr, NULL, -1, 1, -1, 0, (mpz_srcptr)(mpz));
    return ss;
}

inline BICYCL::Mpz deserialize_bicycl_mpz_binary(const String& data) {
    uint32_t num_bytes = data.size() - 1;
    const char* data_ptr = data.data();
    char sign;
    memcpy(&sign, data_ptr, sizeof(char));
    data_ptr += sizeof(char);
    mpz_t mpz;
    mpz_init(mpz);
    mpz_import(mpz, num_bytes, -1, 1, -1, 0, data_ptr);
    BICYCL::Mpz b_mpz(std::move(mpz));
    if (sign == 1) {
        b_mpz.neg();
    }
    return b_mpz;
}

inline std::string serialize_bicycl_qfi_binary(const BICYCL::QFI& qfi) {
    // first 8 bytes are used to hold offsets and signs
    // first 3 bit represent the sign of a, b, c
    // the next 30 bits hold the size of a
    // the next 30 bits hold the size of b
    // the last bit is unused
    uint32_t bytes_in_a =
        (mpz_sizeinbase(static_cast<mpz_srcptr>(qfi.a()), 2) + 7) / 8;
    uint32_t bytes_in_b =
        (mpz_sizeinbase(static_cast<mpz_srcptr>(qfi.b()), 2) + 7) / 8;
    uint32_t bytes_in_c =
        (mpz_sizeinbase(static_cast<mpz_srcptr>(qfi.c()), 2) + 7) / 8;
    uint64_t num_bytes =
        sizeof(uint64_t) + bytes_in_a + bytes_in_b + bytes_in_c;
    std::string ss(num_bytes, 0);
    char* data_ptr = ss.data();
    uint64_t table = (static_cast<uint64_t>(qfi.a().sgn() == 1 ? 0 : 1) << 63) |
                     (static_cast<uint64_t>(qfi.b().sgn() == 1 ? 0 : 1) << 62) |
                     (static_cast<uint64_t>(qfi.c().sgn() == 1 ? 0 : 1) << 61) |
                     (static_cast<uint64_t>(bytes_in_a) << 31) |
                     (static_cast<uint64_t>(bytes_in_b) << 1);
    memcpy(data_ptr, &table, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    // write the data
    mpz_export(data_ptr, NULL, -1, 1, -1, 0, static_cast<mpz_srcptr>(qfi.a()));
    data_ptr += bytes_in_a;
    mpz_export(data_ptr, NULL, -1, 1, -1, 0, static_cast<mpz_srcptr>(qfi.b()));
    data_ptr += bytes_in_b;
    mpz_export(data_ptr, NULL, -1, 1, -1, 0, static_cast<mpz_srcptr>(qfi.c()));
    return ss;
}

inline BICYCL::QFI deserialize_bicycl_qfi_binary(const String& data) {
    uint64_t table;
    const char* data_ptr = data.data();
    memcpy(&table, data_ptr, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    bool is_a_neg = static_cast<bool>(table & (static_cast<uint64_t>(1) << 63));
    bool is_b_neg = static_cast<bool>(table & (static_cast<uint64_t>(1) << 62));
    bool is_c_neg = static_cast<bool>(table & (static_cast<uint64_t>(1) << 61));
    uint32_t bytes_in_a =
        static_cast<uint32_t>(table >> 31) & 0x3FFFFFFF; // 60-31st
    uint32_t bytes_in_b =
        static_cast<uint32_t>(table >> 1) & 0x3FFFFFFF; // 30-1st
    uint32_t bytes_in_c =
        data.size() - sizeof(uint64_t) - bytes_in_a - bytes_in_b;

    mpz_t a, b, c;
    mpz_init(a);
    mpz_init(b);
    mpz_init(c);
    mpz_import(a, bytes_in_a, -1, 1, -1, 0, data_ptr);
    data_ptr += bytes_in_a;
    mpz_import(b, bytes_in_b, -1, 1, -1, 0, data_ptr);
    data_ptr += bytes_in_b;
    mpz_import(c, bytes_in_c, -1, 1, -1, 0, data_ptr);
    BICYCL::Mpz b_a(std::move(a)), b_b(std::move(b)), b_c(std::move(c));
    if (is_a_neg) {
        b_a.neg();
    }
    if (is_b_neg) {
        b_b.neg();
    }
    if (is_c_neg) {
        b_c.neg();
    }
    BICYCL::QFI qfi(std::move(b_a), std::move(b_b), std::move(b_c));
    return qfi;
}

inline String CPUCryptoSystem::serialize_secret_key(
    const CPUCryptoSystem::SecretKey& sk) const {
    return serialize_bicycl_mpz_binary(static_cast<BICYCL::Mpz>(sk));
}

inline CPUCryptoSystem::SecretKey
CPUCryptoSystem::deserialize_secret_key(const String& data) const {
    return CPUCryptoSystem::SecretKey(this->hsm2k,
                                      deserialize_bicycl_mpz_binary(data));
}

inline String CPUCryptoSystem::serialize_secret_key_share(
    const CPUCryptoSystem::SecretKeyShare& sks) const {
    return serialize_bicycl_mpz_binary(sks);
}

inline CPUCryptoSystem::SecretKeyShare
CPUCryptoSystem::deserialize_secret_key_share(const String& data) const {
    return deserialize_bicycl_mpz_binary(data);
}

inline String CPUCryptoSystem::serialize_public_key(
    const CPUCryptoSystem::PublicKey& pk) const {
    return serialize_bicycl_qfi_binary(pk.elt());
}

inline CPUCryptoSystem::PublicKey
CPUCryptoSystem::deserialize_public_key(const String& data) const {
    return CPUCryptoSystem::PublicKey(hsm2k,
                                      deserialize_bicycl_qfi_binary(data));
}

inline String CPUCryptoSystem::serialize_plaintext(
    const CPUCryptoSystem::PlainText& s) const {
    return serialize_bicycl_mpz_binary(s);
}

inline CPUCryptoSystem::PlainText
CPUCryptoSystem::deserialize_plaintext(const String& data) const {
    return deserialize_bicycl_mpz_binary(data);
}

inline String CPUCryptoSystem::serialize_ciphertext(
    const CPUCryptoSystem::CipherText& ct) const {
    // first 8 bytes represent the size of first qfi
    // this implementation can be optimised further if needed
    std::string c1 = serialize_bicycl_qfi_binary(ct.c1());
    std::string c2 = serialize_bicycl_qfi_binary(ct.c2());
    size_t data_size = sizeof(uint64_t) + c1.size() + c2.size();
    std::string data(data_size, 0);
    char* data_ptr = data.data();
    uint64_t size_of_c1 = c1.size();
    memcpy(data_ptr, &size_of_c1, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    memcpy(data_ptr, c1.data(), c1.size());
    data_ptr += c1.size();
    memcpy(data_ptr, c2.data(), c2.size());
    return data;
}

inline CPUCryptoSystem::CipherText
CPUCryptoSystem::deserialize_ciphertext(const String& data) const {
    uint64_t size_of_c1;
    const char* data_ptr = data.data();
    memcpy(&size_of_c1, data_ptr, sizeof(uint64_t));
    data_ptr += sizeof(uint64_t);
    std::string c1_str(data_ptr, size_of_c1);
    data_ptr += size_of_c1;
    std::string c2_str(data_ptr, data.size() - size_of_c1 - sizeof(uint64_t));
    BICYCL::QFI c1 = deserialize_bicycl_qfi_binary(c1_str);
    BICYCL::QFI c2 = deserialize_bicycl_qfi_binary(c2_str);
    return CPUCryptoSystem::CipherText(std::move(c1), std::move(c2));
}

inline String CPUCryptoSystem::serialize_partial_decryption_result(
    const CPUCryptoSystem::PartialDecryptionResult& pdr) const {
    return serialize_bicycl_qfi_binary(pdr);
}

inline CPUCryptoSystem::PartialDecryptionResult
CPUCryptoSystem::deserialize_partial_decryption_result(const String& data) const {
    return deserialize_bicycl_qfi_binary(data);
}

inline String CPUCryptoSystem::serialize_plaintext_tensor(
    const Tensor<CPUCryptoSystem::PlainText*>& s_cpu) const {
    uint32_t ndim = s_cpu.ndim();
    auto cpu_flattened = s_cpu;
    cpu_flattened.flatten();
    size_t data_size = 4 + 4 * ndim + 8 * s_cpu.num_elements();
    std::vector<uint64_t> data_offsets(s_cpu.num_elements());
    uint64_t last_offset = 0;
    for (size_t i = 0; i < s_cpu.num_elements(); i++) {
        data_offsets[i] = last_offset | ((cpu_flattened.at(i)->sgn() != 1
                                              ? ((uint64_t)(1) << 63)
                                              : (uint64_t)(0)));
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(cpu_flattened.at(i)), 2) + 7) / 8;
    }
    data_size += last_offset;
    std::string data(data_size, 0);
    char* data_ptr = data.data();
    // write ndim
    memcpy(data_ptr, &ndim, 4);
    data_ptr += 4;
    // write shape
    for (size_t i = 0; i < s_cpu.ndim(); i++) {
        uint32_t dim = s_cpu.shape()[i];
        memcpy(data_ptr, &dim, 4);
        data_ptr += 4;
    }
    // write pointer table
    for (size_t i = 0; i < s_cpu.num_elements(); i++) {
        memcpy(data_ptr, &data_offsets[i], 8);
        data_ptr += 8;
    }
    // write data
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                            i < s_cpu.num_elements(); i++) {
        mpz_export(data_ptr + (data_offsets[i] & (~((uint64_t)(1) << 63))),
                   NULL, -1, 1, -1, 0, (mpz_srcptr)(cpu_flattened.at(i)));
    }
    return data;
}

inline Tensor<CPUCryptoSystem::PlainText*>
CPUCryptoSystem::deserialize_plaintext_tensor(const String& data) const {
    uint32_t ndim;
    const char* data_ptr = data.data();
    memcpy(&ndim, data_ptr, 4);
    data_ptr += 4;
    std::vector<uint32_t> shape(ndim);
    uint64_t num_elements = 1;
    for (size_t i = 0; i < ndim; i++) {
        memcpy(&shape[i], data_ptr, 4);
        data_ptr += 4;
        num_elements *= shape[i];
    }

    std::vector<uint64_t> data_offsets(num_elements, 0);
    for (size_t i = 0; i < num_elements; i++) {
        memcpy(&data_offsets[i], data_ptr, 8);
        data_ptr += 8;
    }

    std::vector<size_t> shape_vec(shape.begin(), shape.end());
    Tensor<CPUCryptoSystem::PlainText*> plaintexts(shape_vec, nullptr);
    plaintexts.flatten();

    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < num_elements - 1;
                                            i++) {
        mpz_t s;
        mpz_init(s);
        mpz_import(s,
                   ((data_offsets[i + 1]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[i] & (~((uint64_t)(1) << 63))));
        plaintexts.at(i) = new BICYCL::Mpz(std::move(s));
        if (data_offsets[i] & ((uint64_t)(1) << 63)) {
            plaintexts.at(i)->neg();
        }
    }
    // last element
    {
        mpz_t s;
        mpz_init(s);
        mpz_import(
            s,
            data.size() -
                (data_offsets[num_elements - 1] & (~((uint64_t)(1) << 63))) -
                (4 + 4 * ndim + 8 * num_elements),
            -1, 1, -1, 0,
            data_ptr +
                (data_offsets[num_elements - 1] & (~((uint64_t)(1) << 63))));
        plaintexts.at(num_elements - 1) = new BICYCL::Mpz(std::move(s));
        if (data_offsets[num_elements - 1] & ((uint64_t)(1) << 63)) {
            plaintexts.at(num_elements - 1)->neg();
        }
    }
    plaintexts.reshape(shape_vec);
    return plaintexts;
}

inline String CPUCryptoSystem::serialize_ciphertext_tensor(
    const Tensor<CPUCryptoSystem::CipherText*>& ct_cpu)
    const { // the format is binary
    // the first 4 bytes are ndim, then next n*4 bytes are the shape, then the
    // pointer table the pointer table points to the actual bingnums data, each
    // entry is 8 bytes the first 1 bit represents the sign, all others
    // represent the number of limbs the data is stored in binary format order
    // is little endian

    // calculate the size of the data
    auto ct_cpu_flattened = ct_cpu;
    ct_cpu_flattened.flatten();
    size_t data_size =
        4 + 4 * ct_cpu.ndim() + 8 * ct_cpu.num_elements() * 2 * 3;
    std::vector<uint64_t> data_offsets(ct_cpu.num_elements() * 2 * 3);
    uint64_t last_offset = 0;
    size_t limb_size = sizeof(mp_limb_t);
    for (size_t i = 0; i < ct_cpu.num_elements(); i++) {
        // assumes that most significant limb is always unset
        data_offsets[i * 6] =
            last_offset | ((ct_cpu_flattened.at(i)->c1().a().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c1().a().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c1().a()), 2) +
             7) /
            8;
        data_offsets[i * 6 + 1] =
            last_offset | ((ct_cpu_flattened.at(i)->c1().b().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c1().b().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c1().b()), 2) +
             7) /
            8;
        data_offsets[i * 6 + 2] =
            last_offset | ((ct_cpu_flattened.at(i)->c1().c().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c1().c().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c1().c()), 2) +
             7) /
            8;
        data_offsets[i * 6 + 3] =
            last_offset | ((ct_cpu_flattened.at(i)->c2().a().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c2().a().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c2().a()), 2) +
             7) /
            8;
        data_offsets[i * 6 + 4] =
            last_offset | ((ct_cpu_flattened.at(i)->c2().b().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c2().b().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c2().b()), 2) +
             7) /
            8;
        data_offsets[i * 6 + 5] =
            last_offset | ((ct_cpu_flattened.at(i)->c2().c().sgn() != 1
                                ? ((uint64_t)(1) << 63)
                                : (uint64_t)(0)));
        // last_offset += ct_cpu_flattened.at(i)->c2().c().nlimbs() * limb_size;
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(ct_cpu_flattened.at(i)->c2().c()), 2) +
             7) /
            8;
    }
    data_size += last_offset;
    std::string data(data_size, 0);
    char* data_ptr = data.data();
    // write ndim
    uint32_t ndim = ct_cpu.ndim();
    memcpy(data_ptr, &ndim, 4);
    data_ptr += 4;
    // write shape
    for (size_t i = 0; i < ct_cpu.ndim(); i++) {
        uint32_t dim = ct_cpu.shape()[i];
        memcpy(data_ptr, &dim, 4);
        data_ptr += 4;
    }

    // write pointer table
    for (size_t i = 0; i < ct_cpu.num_elements(); i++) {
        for (size_t j = 0; j < 6; j++) {
            memcpy(data_ptr, &data_offsets[i * 6 + j], 8);
            data_ptr += 8;
        }
    }
    // write data
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                            i < ct_cpu.num_elements(); i++) {
        mpz_export(data_ptr + (data_offsets[i * 6] & (~((uint64_t)(1) << 63))),
                   NULL, -1, 1, -1, 0,
                   (mpz_srcptr)(ct_cpu_flattened.at(i)->c1().a()));
        mpz_export(
            data_ptr + (data_offsets[i * 6 + 1] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(ct_cpu_flattened.at(i)->c1().b()));
        mpz_export(
            data_ptr + (data_offsets[i * 6 + 2] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(ct_cpu_flattened.at(i)->c1().c()));
        mpz_export(
            data_ptr + (data_offsets[i * 6 + 3] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(ct_cpu_flattened.at(i)->c2().a()));
        mpz_export(
            data_ptr + (data_offsets[i * 6 + 4] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(ct_cpu_flattened.at(i)->c2().b()));
        mpz_export(
            data_ptr + (data_offsets[i * 6 + 5] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(ct_cpu_flattened.at(i)->c2().c()));
    }
    return data;
}

inline Tensor<CPUCryptoSystem::CipherText*>
CPUCryptoSystem::deserialize_ciphertext_tensor(const String& data) const {
    uint32_t ndim;
    const char* data_ptr = data.data();
    memcpy(&ndim, data_ptr, 4);
    data_ptr += 4;
    std::vector<uint32_t> shape(ndim);
    uint64_t num_elements = 1;
    for (size_t i = 0; i < ndim; i++) {
        memcpy(&shape[i], data_ptr, 4);
        data_ptr += 4;
        num_elements *= shape[i];
    }

    std::vector<uint64_t> data_offsets(num_elements * 2 * 3, 0);
    for (size_t i = 0; i < num_elements * 2 * 3; i++) {
        memcpy(&data_offsets[i], data_ptr, 8);
        data_ptr += 8;
    }

    std::vector<size_t> shape_vec(shape.begin(), shape.end());
    Tensor<CPUCryptoSystem::CipherText*> ciphertexts(shape_vec, nullptr);
    ciphertexts.flatten();

    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < num_elements - 1;
                                            i++) {
        mpz_t c1_a, c1_b, c1_c, c2_a, c2_b, c2_c;
        mpz_init(c1_a);
        mpz_init(c1_b);
        mpz_init(c1_c);
        mpz_init(c2_a);
        mpz_init(c2_b);
        mpz_init(c2_c);
        mpz_import(c1_a,
                   ((data_offsets[i * 6 + 1]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[i * 6] & (~((uint64_t)(1) << 63))));
        mpz_import(c1_b,
                   ((data_offsets[i * 6 + 2]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6 + 1]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 6 + 1] & (~((uint64_t)(1) << 63))));
        mpz_import(c1_c,
                   ((data_offsets[i * 6 + 3]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6 + 2]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 6 + 2] & (~((uint64_t)(1) << 63))));
        mpz_import(c2_a,
                   ((data_offsets[i * 6 + 4]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6 + 3]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 6 + 3] & (~((uint64_t)(1) << 63))));
        mpz_import(c2_b,
                   ((data_offsets[i * 6 + 5]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6 + 4]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 6 + 4] & (~((uint64_t)(1) << 63))));
        mpz_import(c2_c,
                   ((data_offsets[i * 6 + 6]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 6 + 5]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 6 + 5] & (~((uint64_t)(1) << 63))));

        // set the sign
        BICYCL::Mpz c1_a_m(std::move(c1_a)), c1_b_m(std::move(c1_b)),
            c1_c_m(std::move(c1_c)), c2_a_m(std::move(c2_a)),
            c2_b_m(std::move(c2_b)), c2_c_m(std::move(c2_c));
        if (data_offsets[i * 6] & ((uint64_t)(1) << 63)) {
            c1_a_m.neg();
        }
        if (data_offsets[i * 6 + 1] & ((uint64_t)(1) << 63)) {
            c1_b_m.neg();
        }
        if (data_offsets[i * 6 + 2] & ((uint64_t)(1) << 63)) {
            c1_c_m.neg();
        }
        if (data_offsets[i * 6 + 3] & ((uint64_t)(1) << 63)) {
            c2_a_m.neg();
        }
        if (data_offsets[i * 6 + 4] & ((uint64_t)(1) << 63)) {
            c2_b_m.neg();
        }
        if (data_offsets[i * 6 + 5] & ((uint64_t)(1) << 63)) {
            c2_c_m.neg();
        }
        ciphertexts.at(i) = new CPUCryptoSystem::CipherText{
            BICYCL::QFI{c1_a_m, c1_b_m, c1_c_m},
            BICYCL::QFI{c2_a_m, c2_b_m, c2_c_m}};
    }
    {
        mpz_t c1_a, c1_b, c1_c, c2_a, c2_b, c2_c;
        mpz_init(c1_a);
        mpz_init(c1_b);
        mpz_init(c1_c);
        mpz_init(c2_a);
        mpz_init(c2_b);
        mpz_init(c2_c);
        mpz_import(c1_a,
                   (data_offsets[(num_elements - 1) * 6 + 1] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 6]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c1_b,
                   (data_offsets[(num_elements - 1) * 6 + 2] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 6 + 1]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6 + 1] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c1_c,
                   (data_offsets[(num_elements - 1) * 6 + 3] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 6 + 2]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6 + 2] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c2_a,
                   (data_offsets[(num_elements - 1) * 6 + 4] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 6 + 3]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6 + 3] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c2_b,
                   (data_offsets[(num_elements - 1) * 6 + 5] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 6 + 4]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6 + 4] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c2_c,
                   data.size() -
                       (data_offsets[(num_elements - 1) * 6 + 5] &
                        (~((uint64_t)(1) << 63))) -
                       (4 + 4 * ndim + 8 * num_elements * 2 * 3),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 6 + 5] &
                               (~((uint64_t)(1) << 63))));
        // set the sign
        BICYCL::Mpz c1_a_m(std::move(c1_a)), c1_b_m(std::move(c1_b)),
            c1_c_m(std::move(c1_c)), c2_a_m(std::move(c2_a)),
            c2_b_m(std::move(c2_b)), c2_c_m(std::move(c2_c));
        if (data_offsets[(num_elements - 1) * 6] & ((uint64_t)(1) << 63)) {
            c1_a_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 6 + 1] & ((uint64_t)(1) << 63)) {
            c1_b_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 6 + 2] & ((uint64_t)(1) << 63)) {
            c1_c_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 6 + 3] & ((uint64_t)(1) << 63)) {
            c2_a_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 6 + 4] & ((uint64_t)(1) << 63)) {
            c2_b_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 6 + 5] & ((uint64_t)(1) << 63)) {
            c2_c_m.neg();
        }
        ciphertexts.at(num_elements - 1) = new CPUCryptoSystem::CipherText{
            BICYCL::QFI{c1_a_m, c1_b_m, c1_c_m},
            BICYCL::QFI{c2_a_m, c2_b_m, c2_c_m}};
    }
    ciphertexts.reshape(shape_vec);
    return ciphertexts;
}

inline String CPUCryptoSystem::serialize_partial_decryption_result_tensor(
    const Tensor<CPUCryptoSystem::PartialDecryptionResult*>& pdr_cpu) const {
    uint32_t ndim = pdr_cpu.ndim();
    auto pdr_cpu_flattened = pdr_cpu;
    pdr_cpu_flattened.flatten();
    size_t data_size = 4 + 4 * ndim + 8 * pdr_cpu.num_elements() * 3;
    std::vector<uint64_t> data_offsets(pdr_cpu.num_elements() * 3);
    uint64_t last_offset = 0;
    size_t limb_size = sizeof(mp_limb_t);
    for (size_t i = 0; i < pdr_cpu.num_elements(); i++) {
        data_offsets[i * 3] =
            last_offset |
            ((pdr_cpu_flattened.at(i)->a().sgn() != 1 ? ((uint64_t)(1) << 63)
                                                      : (uint64_t)(0)));
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(pdr_cpu_flattened.at(i)->a()), 2) +
             7) /
            8;
        data_offsets[i * 3 + 1] =
            last_offset |
            ((pdr_cpu_flattened.at(i)->b().sgn() != 1 ? ((uint64_t)(1) << 63)
                                                      : (uint64_t)(0)));
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(pdr_cpu_flattened.at(i)->b()), 2) +
             7) /
            8;
        data_offsets[i * 3 + 2] =
            last_offset |
            ((pdr_cpu_flattened.at(i)->c().sgn() != 1 ? ((uint64_t)(1) << 63)
                                                      : (uint64_t)(0)));
        last_offset +=
            (mpz_sizeinbase((mpz_srcptr)(pdr_cpu_flattened.at(i)->c()), 2) +
             7) /
            8;
    }
    data_size += last_offset;
    std::string data(data_size, 0);
    char* data_ptr = data.data();
    // write ndim
    memcpy(data_ptr, &ndim, 4);
    data_ptr += 4;
    // write shape
    for (size_t i = 0; i < pdr_cpu.ndim(); i++) {
        uint32_t dim = pdr_cpu.shape()[i];
        memcpy(data_ptr, &dim, 4);
        data_ptr += 4;
    }
    // write pointer table
    for (size_t i = 0; i < pdr_cpu.num_elements(); i++) {
        for (size_t j = 0; j < 3; j++) {
            memcpy(data_ptr, &data_offsets[i * 3 + j], 8);
            data_ptr += 8;
        }
    }
    // write data
    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0;
                                            i < pdr_cpu.num_elements(); i++) {
        mpz_export(data_ptr + (data_offsets[i * 3] & (~((uint64_t)(1) << 63))),
                   NULL, -1, 1, -1, 0,
                   (mpz_srcptr)(pdr_cpu_flattened.at(i)->a()));
        mpz_export(
            data_ptr + (data_offsets[i * 3 + 1] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(pdr_cpu_flattened.at(i)->b()));
        mpz_export(
            data_ptr + (data_offsets[i * 3 + 2] & (~((uint64_t)(1) << 63))),
            NULL, -1, 1, -1, 0, (mpz_srcptr)(pdr_cpu_flattened.at(i)->c()));
    }
    return data;
}

inline Tensor<CPUCryptoSystem::PartialDecryptionResult*>
CPUCryptoSystem::deserialize_partial_decryption_result_tensor(
    const String& data) const {
    uint32_t ndim;
    const char* data_ptr = data.data();
    memcpy(&ndim, data_ptr, 4);
    data_ptr += 4;
    std::vector<uint32_t> shape(ndim);
    uint64_t num_elements = 1;
    for (size_t i = 0; i < ndim; i++) {
        memcpy(&shape[i], data_ptr, 4);
        data_ptr += 4;
        num_elements *= shape[i];
    }

    std::vector<uint64_t> data_offsets(num_elements * 3, 0);
    for (size_t i = 0; i < num_elements * 3; i++) {
        memcpy(&data_offsets[i], data_ptr, 8);
        data_ptr += 8;
    }

    std::vector<size_t> shape_vec(shape.begin(), shape.end());
    Tensor<CPUCryptoSystem::PartialDecryptionResult*> part_decryption_results(
        shape_vec, nullptr);
    part_decryption_results.flatten();

    CoFHE_PARALLEL_FOR_STATIC_SCHEDULE for (size_t i = 0; i < num_elements - 1;
                                            i++) {
        mpz_t a, b, c;
        mpz_init(a);
        mpz_init(b);
        mpz_init(c);
        mpz_import(a,
                   ((data_offsets[i * 3 + 1]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 3]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[i * 3] & (~((uint64_t)(1) << 63))));
        mpz_import(b,
                   ((data_offsets[i * 3 + 2]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 3 + 1]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 3 + 1] & (~((uint64_t)(1) << 63))));
        mpz_import(c,
                   ((data_offsets[i * 3 + 3]) & (~((uint64_t)(1) << 63))) -
                       ((data_offsets[i * 3 + 2]) & (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr +
                       (data_offsets[i * 3 + 2] & (~((uint64_t)(1) << 63))));
        BICYCL::Mpz a_m(std::move(a)), b_m(std::move(b)), c_m(std::move(c));
        if (data_offsets[i * 3] & ((uint64_t)(1) << 63)) {
            a_m.neg();
        }
        if (data_offsets[i * 3 + 1] & ((uint64_t)(1) << 63)) {
            b_m.neg();
        }
        if (data_offsets[i * 3 + 2] & ((uint64_t)(1) << 63)) {
            c_m.neg();
        }
        part_decryption_results.at(i) =
            new CPUCryptoSystem::PartialDecryptionResult{
                BICYCL::Mpz{a_m}, BICYCL::Mpz{b_m}, BICYCL::Mpz{c_m}};
    }
    {
        mpz_t a, b, c;
        mpz_init(a);
        mpz_init(b);
        mpz_init(c);
        mpz_import(a,
                   (data_offsets[(num_elements - 1) * 3 + 1] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 3]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 3] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(b,
                   (data_offsets[(num_elements - 1) * 3 + 2] &
                    (~((uint64_t)(1) << 63))) -
                       ((data_offsets[(num_elements - 1) * 3 + 1]) &
                        (~((uint64_t)(1) << 63))),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 3 + 1] &
                               (~((uint64_t)(1) << 63))));
        mpz_import(c,
                   data.size() -
                       (data_offsets[(num_elements - 1) * 3 + 2] &
                        (~((uint64_t)(1) << 63))) -
                       (4 + 4 * ndim + 8 * num_elements * 3),
                   -1, 1, -1, 0,
                   data_ptr + (data_offsets[(num_elements - 1) * 3 + 2] &
                               (~((uint64_t)(1) << 63))));
        BICYCL::Mpz a_m(std::move(a)), b_m(std::move(b)), c_m(std::move(c));
        if (data_offsets[(num_elements - 1) * 3] & ((uint64_t)(1) << 63)) {
            a_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 3 + 1] & ((uint64_t)(1) << 63)) {
            b_m.neg();
        }
        if (data_offsets[(num_elements - 1) * 3 + 2] & ((uint64_t)(1) << 63)) {
            c_m.neg();
        }
        part_decryption_results.at(num_elements - 1) =
            new CPUCryptoSystem::PartialDecryptionResult{
                BICYCL::Mpz{a_m}, BICYCL::Mpz{b_m}, BICYCL::Mpz{c_m}};
    }
    part_decryption_results.reshape(shape_vec);
    return part_decryption_results;
}