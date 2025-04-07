#ifndef COFHE_RSA_HPP_INCLUDED
#define COFHE_RSA_HPP_INCLUDED

#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace CoFHE {
class RSAPKCEncryptor {
  public:
    struct PKEYDeleter {
        void operator()(EVP_PKEY* pkey) const {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    };
    using Message = std::string;
    using EncryptedMessage = std::string;
    using KeyPair = std::unique_ptr<EVP_PKEY, PKEYDeleter>;

    RSAPKCEncryptor(uint32_t key_size) : key_size_m(key_size) {
        init_openssl();
    }
    ~RSAPKCEncryptor() {
        cleanup_openssl();
    }

    KeyPair generate_key_pair() const {
        unique_pkey_ctx_ptr keygen_ctx(
            EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!keygen_ctx) {
            handle_openssl_errors("EVP_PKEY_CTX_new_id failed");
        }

        if (EVP_PKEY_keygen_init(keygen_ctx.get()) <= 0) {
            handle_openssl_errors("EVP_PKEY_keygen_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx.get(), key_size_m) <=
            0) {
            handle_openssl_errors("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }

        KeyPair pkey(nullptr);
        EVP_PKEY* pkey_raw = nullptr;
        if (EVP_PKEY_keygen(keygen_ctx.get(), &pkey_raw) <= 0) {
            handle_openssl_errors("EVP_PKEY_keygen failed");
        }
        pkey.reset(pkey_raw);
        return pkey;
    }

    std::string serialize_private_key(const KeyPair& pkey) const {
        if (!pkey) {
            throw std::invalid_argument("EVP_PKEY is null for serialization.");
        }

        unique_bio_ptr bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            handle_openssl_errors("BIO_new failed");
        }

        if (i2d_PrivateKey_bio(bio.get(), pkey.get()) <= 0) {
            handle_openssl_errors("i2d_PrivateKey_bio failed");
        }

        BUF_MEM* buffer_ptr;
        BIO_get_mem_ptr(bio.get(), &buffer_ptr);
        if (!buffer_ptr || !buffer_ptr->data || buffer_ptr->length == 0) {
            throw std::runtime_error("Failed to get data from BIO memory "
                                     "buffer after serialization.");
        }
        return std::string(buffer_ptr->data, buffer_ptr->length);
    }

    std::string serialize_public_key(const KeyPair& pkey) const {
        if (!pkey) {
            throw std::invalid_argument("EVP_PKEY is null for serialization.");
        }

        unique_bio_ptr bio(BIO_new(BIO_s_mem()));
        if (!bio) {
            handle_openssl_errors("BIO_new failed");
        }

        if (i2d_PUBKEY_bio(bio.get(), pkey.get()) <= 0) {
            handle_openssl_errors("i2d_PUBKEY_bio failed");
        }

        BUF_MEM* buffer_ptr;
        BIO_get_mem_ptr(bio.get(), &buffer_ptr);
        if (!buffer_ptr || !buffer_ptr->data || buffer_ptr->length == 0) {
            throw std::runtime_error("Failed to get data from BIO memory "
                                     "buffer after serialization.");
        }
        return std::string(buffer_ptr->data, buffer_ptr->length);
    }

    KeyPair deserialize_private_key(const std::string& der_data) const {
        if (der_data.empty()) {
            throw std::invalid_argument(
                "DER data is empty for deserialization.");
        }

        unique_bio_ptr bio(BIO_new_mem_buf(der_data.data(),
                                           static_cast<int>(der_data.size())));
        if (!bio) {
            handle_openssl_errors("BIO_new_mem_buf failed");
        }

        EVP_PKEY* pkey_priv = nullptr;
        pkey_priv = d2i_PrivateKey_bio(bio.get(), nullptr);
        if (!pkey_priv) {
            handle_openssl_errors("d2i_PrivateKey_bio failed");
        }
        return KeyPair(pkey_priv);
    }

    KeyPair deserialize_public_key(const std::string& der_data) const {
        if (der_data.empty()) {
            throw std::invalid_argument(
                "DER data is empty for deserialization.");
        }

        unique_bio_ptr bio(BIO_new_mem_buf(der_data.data(),
                                           static_cast<int>(der_data.size())));
        if (!bio) {
            handle_openssl_errors("BIO_new_mem_buf failed");
        }

        EVP_PKEY* pkey_pub = nullptr;
        pkey_pub = d2i_PUBKEY_bio(bio.get(), nullptr);
        if (!pkey_pub) {
            handle_openssl_errors("d2i_PUBKEY_bio failed");
        }
        return KeyPair(pkey_pub);
    }

    EncryptedMessage encrypt(const KeyPair& pkey,
                             const Message& plaintext) const {
        if (!pkey) {
            throw std::invalid_argument("EVP_PKEY is null for encryption.");
        }

        unique_pkey_ctx_ptr enc_ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (!enc_ctx) {
            handle_openssl_errors("EVP_PKEY_CTX_new for encryption failed");
        }

        if (EVP_PKEY_encrypt_init(enc_ctx.get()) <= 0) {
            handle_openssl_errors("EVP_PKEY_encrypt_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx.get(), RSA_PKCS1_PADDING) <=
            0) {
            handle_openssl_errors("EVP_PKEY_CTX_set_rsa_padding failed");
        }

        size_t encrypted_len_out = 0;
        if (EVP_PKEY_encrypt(
                enc_ctx.get(), nullptr, &encrypted_len_out,
                reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                plaintext.length()) <= 0) {
            handle_openssl_errors("EVP_PKEY_encrypt (length check) failed");
        }

        std::string ciphertext(encrypted_len_out, '\0');
        if (EVP_PKEY_encrypt(
                enc_ctx.get(), reinterpret_cast<unsigned char*>(&ciphertext[0]),
                &encrypted_len_out,
                reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                plaintext.length()) <= 0) {
            handle_openssl_errors("EVP_PKEY_encrypt failed");
        }
        ciphertext.resize(encrypted_len_out);
        return ciphertext;
    }

    Message decrypt(const KeyPair& pkey,
                    const EncryptedMessage& ciphertext) const {
        if (!pkey) {
            throw std::invalid_argument("EVP_PKEY is null for decryption.");
        }

        unique_pkey_ctx_ptr dec_ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (!dec_ctx) {
            handle_openssl_errors("EVP_PKEY_CTX_new for decryption failed");
        }

        if (EVP_PKEY_decrypt_init(dec_ctx.get()) <= 0) {
            handle_openssl_errors("EVP_PKEY_decrypt_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx.get(), RSA_PKCS1_PADDING) <=
            0) {
            handle_openssl_errors("EVP_PKEY_CTX_set_rsa_padding failed");
        }

        size_t decrypted_len_out = 0;
        if (EVP_PKEY_decrypt(
                dec_ctx.get(), nullptr, &decrypted_len_out,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.length()) <= 0) {
            handle_openssl_errors("EVP_PKEY_decrypt (length check) failed");
        }

        std::string decryptedtext(decrypted_len_out, '\0');
        if (EVP_PKEY_decrypt(
                dec_ctx.get(),
                reinterpret_cast<unsigned char*>(&decryptedtext[0]),
                &decrypted_len_out,
                reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
                ciphertext.length()) <= 0) {
            handle_openssl_errors("EVP_PKEY_decrypt failed");
        }
        decryptedtext.resize(decrypted_len_out);
        return decryptedtext;
    }

    void handle_openssl_errors(const std::string& context_message = "") const {
        unsigned long err_code;
        char err_buf[256];
        std::stringstream ss;
        ss << "OpenSSL Error";
        if (!context_message.empty()) {
            ss << " (" << context_message << ")";
        }
        ss << ":" << std::endl;
        while ((err_code = ERR_get_error()) != 0) {
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            ss << " - " << err_buf << std::endl;
        }

        throw std::runtime_error(ss.str());
    }

  private:
    uint32_t key_size_m;

    struct PKEYCTXDeleter {
        void operator()(EVP_PKEY_CTX* ctx) const {
            if (ctx) {
                EVP_PKEY_CTX_free(ctx);
            }
        }
    };
    using unique_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, PKEYCTXDeleter>;
    struct BIODeleter {
        void operator()(BIO* bio) const {
            if (bio) {
                BIO_free_all(bio);
            }
        }
    };
    using unique_bio_ptr = std::unique_ptr<BIO, BIODeleter>;

    static bool init_openssl() {
        static bool initialized = false;
        if (!initialized) {
            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            initialized = true;
        }
        return initialized;
    }

    static bool cleanup_openssl() {
        // implement this
        return true;
    }
};
} // namespace CoFHE

#endif // COFHE_RSA_HPP_INCLUDED