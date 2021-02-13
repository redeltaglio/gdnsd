/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>
#include "dnssec_alg.h"

#include "dnswire.h"

#include <string.h>
#include <arpa/inet.h>

#include <gdnsd/alloc.h>
#include <gdnsd/log.h>

#include <sodium.h>

#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

// For fatals during key gen/load
#define GTLS_CALL(expr) do {\
    int _erv = (expr);\
    if (unlikely(_erv < 0))\
        log_fatal("gnutls call failed: " #expr " -> %s", gnutls_strerror(_erv));\
} while(0);

F_NONNULL
static uint8_t* gtls_p256_init_sk(zsk_t* zsk)
{
    gnutls_privkey_t sk;

    // Generate the privkey
    GTLS_CALL(gnutls_privkey_init(&sk));
    GTLS_CALL(gnutls_privkey_generate(sk, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0));

    // DNSKEY rdata (most of it anyways)
    const unsigned dnskey_rdlen = 4U + 64U;
    uint8_t* dnskey_rdata = xmalloc(2U + dnskey_rdlen);
    gdnsd_put_una16(htons(dnskey_rdlen), dnskey_rdata);
    memcpy(&dnskey_rdata[2], "\1\1\3\15", 4U); // ZK=1, SEP=1, PROTO=3, ALG=P256
    uint8_t* pk_out = &dnskey_rdata[6]; // Write the 64-byte pubkey here

    // Get the pubkey for the privkey and convert to x|y suitable for dnssec
    gnutls_pubkey_t pk;
    gnutls_pubkey_init(&pk);
    GTLS_CALL(gnutls_pubkey_import_privkey(pk, sk, 0, 0));
    gnutls_datum_t x = { 0 };
    gnutls_datum_t y = { 0 };
    GTLS_CALL(gnutls_pubkey_export_ecc_raw2(pk, NULL, &x, &y, GNUTLS_EXPORT_FLAG_NO_LZ));
    gdnsd_assert(x.size <= 32U);
    gdnsd_assert(y.size <= 32U);
    memset(pk_out, 0, 64U);
    memcpy(&pk_out[32U - x.size], x.data, x.size);
    memcpy(&pk_out[64U - y.size], y.data, y.size);

    gnutls_free(y.data);
    gnutls_free(x.data);
    gnutls_pubkey_deinit(pk);

    zsk->sk = sk;
    return dnskey_rdata;
}

F_NONNULL
static unsigned gtls_p256_sign(const zsk_t* zsk, uint8_t* out, uint8_t* in, const unsigned in_len, gnutls_privkey_flags_t flags)
{
    // This gives us all-zeros in case of error, and it also pre-fills zeros
    // for the case where gnutls_decode_rs_value gives short outputs
    memset(out, 0, 64U);

    gnutls_privkey_t sk = zsk->sk;
    const gnutls_datum_t input = { in, in_len };
    gnutls_datum_t sig = { 0 };
    int gtls_rv = gnutls_privkey_sign_data(sk, GNUTLS_DIG_SHA256, flags, &input, &sig);
    if (gtls_rv < 0) {
        log_neterr("P256 signing failed: %s", gnutls_strerror(gtls_rv));
        return 64U;
    }

    // Convert from ASN.1 to raw values r|s, very clumsily
    gnutls_datum_t g_r = { 0 };
    gnutls_datum_t g_s = { 0 };
    gtls_rv = gnutls_decode_rs_value(&sig, &g_r, &g_s);
    if (gtls_rv < 0) {
        log_neterr("P256 signature decode failed: %s", gnutls_strerror(gtls_rv));
        return 64U;
    }

    uint8_t* r = g_r.data;
    if (g_r.size > 32U) {
        gdnsd_assert(g_r.size == 33U);
        g_r.size = 32U;
        r++;
    }
    uint8_t* s = g_s.data;
    if (g_s.size > 32U) {
        gdnsd_assert(g_s.size == 33U);
        g_s.size = 32U;
        s++;
    }
    memcpy(&out[32U - g_r.size], r, g_r.size);
    memcpy(&out[64U - g_s.size], s, g_s.size);

    gnutls_free(g_s.data);
    gnutls_free(g_r.data);
    gnutls_free(sig.data);

    return 64U;
}

// This un-gracefully covers up the fact that gtls_p256_sign_foo's "in" param below
// should be "const", but isn't :/
// The reason is that gnutls_datum_t wraps data pointers for the library's
// function arguments, but doesn't have a const variant that wraps const
// pointers, and all other solutions seem even uglier on some level.
#define gtls_p256_sign_cast_hack unsigned(*)(const zsk_t*,uint8_t*,const uint8_t*,const unsigned)

F_NONNULL
static unsigned gtls_p256_sign_d(const zsk_t* zsk, uint8_t* out, uint8_t* in, const unsigned in_len)
{
    return gtls_p256_sign(zsk, out, in, in_len, GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE);
}

// F_UNUSED for the case where both libraries are loaded
F_NONNULL F_UNUSED
static unsigned gtls_p256_sign_nd(const zsk_t* zsk, uint8_t* out, uint8_t* in, const unsigned in_len)
{
    return gtls_p256_sign(zsk, out, in, in_len, 0);
}


F_NONNULL
static void gtls_p256_wipe_sk(zsk_t* zsk)
{
    gnutls_privkey_deinit(zsk->sk);
}

#endif // HAVE_GNUTLS

#ifdef HAVE_LIBCRYPTO

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

static const char* logf_libcrypto(void)
{
    char tmpbuf[1024];
    unsigned long e = ERR_get_error();
    ERR_error_string_n(e, tmpbuf, 1024U);
    const size_t elen = strlen(tmpbuf) + 1U;
    char* dnbuf = gdnsd_fmtbuf_alloc(elen);
    memcpy(dnbuf, tmpbuf, elen);
    return dnbuf;
}

F_NONNULL
static uint8_t* ossl_p256_init_sk(zsk_t* zsk)
{
    EC_KEY* sk = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (sk == NULL)
        log_fatal("Key init failed: %s", logf_libcrypto());
    if (EC_KEY_generate_key(sk) == 0)
        log_fatal("Key gen failed: %s", logf_libcrypto());

    const unsigned dnskey_rdlen = 4U + 64U;
    uint8_t* dnskey_rdata = xmalloc(2U + dnskey_rdlen);
    gdnsd_put_una16(htons(dnskey_rdlen), dnskey_rdata);
    memcpy(&dnskey_rdata[2], "\1\1\3\15", 4U); // ZK=1, SEP=1, PROTO=3, ALG=P256
    uint8_t* pk_out = &dnskey_rdata[6]; // Write the 64-byte pubkey here

    uint8_t* pub_out;
    size_t len = EC_POINT_point2buf(EC_KEY_get0_group(sk),
                                    EC_KEY_get0_public_key(sk),
                                    POINT_CONVERSION_UNCOMPRESSED,
                                    &pub_out, NULL);
    if (!len)
        log_fatal("Pubkey extraction failed: %s", logf_libcrypto());
    gdnsd_assert(len == 65U);
    memcpy(pk_out, &pub_out[1], 64U);
    OPENSSL_free(pub_out);

    zsk->sk = sk;
    return dnskey_rdata;
}

F_NONNULL
static unsigned ossl_p256_sign(const zsk_t* zsk, uint8_t* out, const uint8_t* in, const unsigned in_len)
{
    // This gives us all-zeros in case of error, and it also pre-fills zeros
    // for the case where BN_bn2bin gives short outputs
    memset(out, 0, 64U);

    EC_KEY* sk = zsk->sk;
    uint8_t in_sha256[SHA256_DIGEST_LENGTH];
    SHA256(in, in_len, in_sha256);
    ECDSA_SIG* sig = ECDSA_do_sign(in_sha256, SHA256_DIGEST_LENGTH, sk);
    if (unlikely(!sig)) {
        log_neterr("P256 signing failed: %s", logf_libcrypto());
        return 64U;
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);
    uint8_t tmp[32U];
    const int r_len = BN_bn2bin(r, tmp);
    gdnsd_assert(r_len && r_len <= 32);
    memcpy(&out[32 - r_len], tmp, (size_t)r_len);
    const int s_len = BN_bn2bin(s, tmp);
    gdnsd_assert(s_len && s_len <= 32);
    memcpy(&out[64 - s_len], tmp, (size_t)s_len);

    ECDSA_SIG_free(sig);

    return 64U;
}

F_NONNULL
static void ossl_p256_wipe_sk(zsk_t* z)
{
    EC_KEY_free(z->sk);
}

#endif // HAVE_LIBCRYPTO

F_NONNULL
static uint8_t* ed25519_init_sk(zsk_t* zsk)
{
    // DNSKEY rdata
    const unsigned dnskey_rdlen = 4U + crypto_sign_ed25519_PUBLICKEYBYTES;
    uint8_t* dnskey_rdata = xmalloc(2U + dnskey_rdlen);
    gdnsd_put_una16(htons(dnskey_rdlen), dnskey_rdata);
    memcpy(&dnskey_rdata[2], "\1\1\3\17", 4U); // ZK=1, SEP=1, PROTO=3, ALG=ED25519

    // Create the secret key while writing the pubkey into the rdata above
    uint8_t* sk = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES);
    if (crypto_sign_ed25519_keypair(&dnskey_rdata[6], sk)) {
        log_err("sodium_signed_ed25519_keypair failed: %s", logf_errno());
        free(dnskey_rdata);
        sodium_free(sk);
        return NULL;
    }

    zsk->sk = sk;
    return dnskey_rdata;
}

F_NONNULL
static unsigned ed25519_sign(const zsk_t* zsk, uint8_t* out, const uint8_t* in, const unsigned in_len)
{
    gdnsd_assert(zsk->alg->sig_len == crypto_sign_ed25519_BYTES);
    crypto_sign_ed25519_detached(out, NULL, in, in_len, zsk->sk);
    return crypto_sign_ed25519_BYTES;
}

F_NONNULL
static void ed25519_wipe_sk(zsk_t* zsk)
{
    sodium_free(zsk->sk);
}

static const alg_t algs[] = {
    {
        .id = DNSSEC_ALG_ED25519,
        .flags = ALG_DETERMINISTIC,
        .sig_len = crypto_sign_ed25519_BYTES,
        .init_sk = ed25519_init_sk,
        .sign = ed25519_sign,
        .wipe_sk = ed25519_wipe_sk,
        .bench_desc = "Ed25519 (libsodium, deterministic)",
    },

#if defined HAVE_LIBCRYPTO
    {
        .id = DNSSEC_ALG_ECDSAP256SHA256,
        .flags = 0,
        .sig_len = 64U,
        .init_sk = ossl_p256_init_sk,
        .sign = ossl_p256_sign,
        .wipe_sk = ossl_p256_wipe_sk,
        .bench_desc = "P256 (libcrypto, non-deterministic)",
    },
#elif defined HAVE_GNUTLS
    {
        .id = DNSSEC_ALG_ECDSAP256SHA256,
        .flags = 0,
        .sig_len = 64U,
        .init_sk = gtls_p256_init_sk,
        .sign = (gtls_p256_sign_cast_hack)gtls_p256_sign_nd,
        .wipe_sk = gtls_p256_wipe_sk,
        .bench_desc = "P256 (libgnutls, non-deterministic)",
    },
#endif

#ifdef HAVE_GNUTLS
    {
        .id = DNSSEC_ALG_ECDSAP256SHA256,
        .flags = ALG_DETERMINISTIC,
        .sig_len = 64U,
        .init_sk = gtls_p256_init_sk,
        .sign = (gtls_p256_sign_cast_hack)gtls_p256_sign_d,
        .wipe_sk = gtls_p256_wipe_sk,
        .bench_desc = "P256 (libgnutls, deterministic)",
    },
#endif
};

uint8_t* dnssec_alg_init_zsk(zsk_t* zsk, unsigned algid, unsigned req_flags)
{
    for (unsigned i = 0; i < ARRAY_SIZE(algs); i++) {
        if (algid == algs[i].id && (req_flags & algs[i].flags) == req_flags) {
            zsk->alg = &algs[i];
            return zsk->alg->init_sk(zsk);
        }
    }
    return NULL;
}

void dnssec_alg_init_global(void)
{
#if HAVE_LIBCRYPTO
    ERR_load_crypto_strings();
#endif
}
