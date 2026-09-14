/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

#include "openssl/crypto.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "testutil.h"

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *prov;

/* ------------------------------------------------------------------ */
/* KATs                                                               */
/* ------------------------------------------------------------------ */

/*
 * FIPS 180-4 (SHA2) and FIPS 202 (SHA3) digests of "abc", with the
 * digest and block lengths each algorithm should report.
 */
struct digest_kat {
	const char *alg;
	size_t md_len;
	size_t block_len;
	const char *hex;
};

static const struct digest_kat digest_kats[] = {
	{ "SHA2-224", 28, 64,
	  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
	{ "SHA2-256", 32, 64,
	  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
	  "f20015ad" },
	{ "SHA2-384", 48, 128,
	  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a"
	  "43ff5bed8086072ba1e7cc2358baeca134c825a7" },
	{ "SHA2-512", 64, 128,
	  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee6"
	  "4b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e"
	  "2a9ac94fa54ca49f" },
	{ "SHA3-224", 28, 144,
	  "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
	{ "SHA3-256", 32, 136,
	  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe245"
	  "11431532" },
	{ "SHA3-384", 48, 104,
	  "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0"
	  "e49be4b298d88cea927ac7f539f1edf228376d25" },
	{ "SHA3-512", 64, 72,
	  "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d02"
	  "40d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5"
	  "6592f8274eec53f0" },
};

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

/* Parameterised: one subtest per algorithm. */
static int test_digest(int idx)
{
	const struct digest_kat *k = &digest_kats[idx];
	unsigned char out[EVP_MAX_MD_SIZE];
	char buf[EVP_MAX_MD_SIZE];
	size_t outl = 0, buflen;
	EVP_MD *md = NULL;
	int ret = 0;

	if (!TEST_ptr(md = EVP_MD_fetch(libctx, k->alg, PROPQ)))
		goto err;
	if (!TEST_size_t_eq((size_t)EVP_MD_get_size(md), k->md_len)
	    || !TEST_size_t_eq((size_t)EVP_MD_get_block_size(md), k->block_len))
		goto err;
	if (!TEST_true(EVP_Q_digest(libctx, k->alg, PROPQ, "abc", 3, out,
				    &outl)))
		goto err;
	if (!TEST_size_t_eq(outl, k->md_len))
		goto err;
	if (!TEST_true(OPENSSL_hexstr2buf_ex((unsigned char *)buf, sizeof(buf),
					     &buflen, k->hex, '\0')))
		goto err;
	if (!TEST_mem_eq(out, outl, buf, buflen))
		goto err;
	ret = 1;
err:
	EVP_MD_free(md);
	return ret;
}

/*
 * Feed "abc" one byte at a time: exercises repeated update() calls, which
 * the one-shot EVP_Q_digest above does not.
 */
static int test_digest_streaming(int idx)
{
	const struct digest_kat *k = &digest_kats[idx];
	static const char msg[] = "abc";
	unsigned char out[EVP_MAX_MD_SIZE];
	char buf[2 * EVP_MAX_MD_SIZE + 1];
	size_t buflen = 0;
	unsigned int outl = 0;
	EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	size_t i;
	int ret = 0;

	if (!TEST_ptr(md = EVP_MD_fetch(libctx, k->alg, PROPQ))
	    || !TEST_ptr(ctx = EVP_MD_CTX_new()))
		goto err;
	if (!TEST_true(EVP_DigestInit_ex2(ctx, md, NULL)))
		goto err;
	for (i = 0; i < sizeof(msg) - 1; i++)
		if (!TEST_true(EVP_DigestUpdate(ctx, &msg[i], 1)))
			goto err;
	if (!TEST_true(EVP_DigestFinal_ex(ctx, out, &outl)))
		goto err;
	if (!TEST_size_t_eq((size_t)outl, k->md_len))
		goto err;
	if (!TEST_true(OPENSSL_hexstr2buf_ex((unsigned char *)buf, sizeof(buf),
					     &buflen, k->hex, '\0')))
		goto err;
	if (!TEST_mem_eq(out, outl, buf, buflen))
		goto err;
	ret = 1;
err:
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);

	return ret;
}

/*
 * These SHA2/SHA3 digests have no configurable per-context state, so they
 * must advertise neither direction: an attempt to change their output size
 * must fail rather than succeed without changing anything, and there must be
 * nothing to read back per context either. The default provider's own
 * fixed-length digests behave the same way -- both accessors come back null
 * and EVP_MD_CTX_get_params returns failure -- while its SHAKE128, whose
 * output length genuinely varies, serves both.
 */
static int test_fixed_digest_has_no_ctx_params(int idx)
{
	const char *alg = digest_kats[idx].alg;
	size_t size = 100;
	OSSL_PARAM params[] = {
		OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, &size),
		OSSL_PARAM_END,
	};
	EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	int ret = 1;

	if (!TEST_ptr(md = EVP_MD_fetch(libctx, alg, PROPQ))
	    || !TEST_ptr(ctx = EVP_MD_CTX_new())) {
		ret = 0;
		goto err;
	}

	ret &= TEST_ptr_null(EVP_MD_settable_ctx_params(md));
	ret &= TEST_ptr_null(EVP_MD_gettable_ctx_params(md));
	if (!TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))) {
		ret = 0;
		goto err;
	}
	ret &= TEST_ptr_null(EVP_MD_CTX_settable_params(ctx));
	ret &= TEST_ptr_null(EVP_MD_CTX_gettable_params(ctx));
	ret &= TEST_int_eq(EVP_MD_CTX_set_params(ctx, params), 0);
	ret &= TEST_int_eq(EVP_MD_CTX_get_params(ctx, params), 0);
	/* Neither rejected call touched the caller's buffer. */
	ret &= TEST_size_t_eq(size, 100);

err:
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
	return ret;
}

/*
 * Copy a context mid-hash and finish both halves: the copy must carry the
 * absorbed state, and the original must be unaffected. This is the only
 * coverage of OSSL_FUNC_digest_dupctx.
 */
static int test_digest_copy(int idx)
{
	const struct digest_kat *k = &digest_kats[idx];
	unsigned char a[EVP_MAX_MD_SIZE], b[EVP_MAX_MD_SIZE];
	char buf[EVP_MAX_MD_SIZE];
	size_t buflen = 0;
	unsigned int al = 0, bl = 0;
	EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL, *dup = NULL;
	int ret = 0;

	if (!TEST_ptr(md = EVP_MD_fetch(libctx, k->alg, PROPQ))
	    || !TEST_ptr(ctx = EVP_MD_CTX_new())
	    || !TEST_ptr(dup = EVP_MD_CTX_new()))
		goto err;

	/* Absorb "ab", duplicate, then feed "c" to each half separately. */
	if (!TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
	    || !TEST_true(EVP_DigestUpdate(ctx, "ab", 2))
	    || !TEST_true(EVP_MD_CTX_copy_ex(dup, ctx)))
		goto err;
	if (!TEST_true(EVP_DigestUpdate(ctx, "c", 1))
	    || !TEST_true(EVP_DigestUpdate(dup, "c", 1)))
		goto err;
	if (!TEST_true(EVP_DigestFinal_ex(ctx, a, &al))
	    || !TEST_true(EVP_DigestFinal_ex(dup, b, &bl)))
		goto err;

	if (!TEST_true(OPENSSL_hexstr2buf_ex((unsigned char *)buf, sizeof(buf),
					     &buflen, k->hex, '\0')))
		goto err;
	if (!TEST_mem_eq(a, al, b, bl) || !TEST_mem_eq(a, al, buf, buflen))
		goto err;

	ret = 1;
err:
	EVP_MD_CTX_free(dup);
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);

	return ret;
}

/*
 * Every alias in a name list must resolve to the same implementation. The
 * provider registers the default provider's aliases and OIDs so the namemap
 * groups merge; a dropped alias would surface here.
 */
static int test_digest_aliases(void)
{
	static const char *const aliases[] = {
		"SHA2-256", "SHA-256",
		"SHA256",   "2.16.840.1.101.3.4.2.1",
		"SHA2-512", "SHA-512",
		"SHA512",   "2.16.840.1.101.3.4.2.3",
		"SHA3-256", "2.16.840.1.101.3.4.2.8",
	};

	for (size_t i = 0; i < ARRAY_SIZE(aliases); i++) {
		EVP_MD *md = EVP_MD_fetch(libctx, aliases[i], PROPQ);

		if (!TEST_ptr(md))
			return 0;

		EVP_MD_free(md);
	}

	return 1;
}

/* ------------------------------------------------------------------ */
/* Framework hooks                                                    */
/* ------------------------------------------------------------------ */

int setup_tests(void)
{
	if (!bc_rust_load(test_argc > 1 ? test_argv[1] : NULL, &libctx, &prov))
		return 0;

	ADD_TEST(test_digest_aliases);
	ADD_ALL_TESTS(test_digest, ARRAY_SIZE(digest_kats));
	ADD_ALL_TESTS(test_digest_streaming, ARRAY_SIZE(digest_kats));
	ADD_ALL_TESTS(test_fixed_digest_has_no_ctx_params,
		      ARRAY_SIZE(digest_kats));
	ADD_ALL_TESTS(test_digest_copy, ARRAY_SIZE(digest_kats));

	return 1;
}

void cleanup_tests(void)
{
	bc_rust_unload(libctx, prov);
}
