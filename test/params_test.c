/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

#include "testutil.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <string.h>

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *prov, *default_prov = NULL;
static OSSL_PROVIDER *params_prov;
static EVP_MD *params_md;
static const char *const propqueries[] = { "provider=default", PROPQ };

/* Each provider is tested with zero and normal data_size, always NULL data. */
static int test_size_query(int idx)
{
	OSSL_PARAM req[] = { OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
			     OSSL_PARAM_END };
	EVP_MD *md = NULL;
	int ret = 0;

	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(size_t);
	TEST_note("%s: size query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	if (!TEST_ptr(md = EVP_MD_fetch(libctx, "SHA2-256",
					propqueries[idx / 2])))
		goto err;
	if (!TEST_int_eq(EVP_MD_get_size(md), 32))
		goto err;

	/* Check both results even on failure, to expose an unchanged
	 * return_size. */
	ret = TEST_true(EVP_MD_get_params(md, req));
	ret &= TEST_size_t_eq(req[0].return_size, sizeof(size_t));
	ret &= TEST_ptr_null(req[0].data);
err:
	EVP_MD_free(md);
	return ret;
}

static int test_status_query(int idx)
{
	OSSL_PROVIDER *p = idx / 2 == 0 ? default_prov : prov;
	OSSL_PARAM req[] = { OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
			     OSSL_PARAM_END };
	int ret;

	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(int);
	TEST_note("%s: status query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	ret = TEST_true(OSSL_PROVIDER_get_params(p, req));
	ret &= TEST_size_t_eq(req[0].return_size, sizeof(int));
	ret &= TEST_ptr_null(req[0].data);
	return ret;
}

static int test_name_query(int idx)
{
	OSSL_PROVIDER *p = idx / 2 == 0 ? default_prov : prov;
	const char *name = NULL;
	OSSL_PARAM value[] = { OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name,
						   0),
			       OSSL_PARAM_END };
	OSSL_PARAM req[] = { OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
			     OSSL_PARAM_END };
	int ret;

	/* UTF8_PTR reports the string length, excluding NUL, not pointer size.
	 */
	if (!TEST_true(OSSL_PROVIDER_get_params(p, value)) || !TEST_ptr(name))
		return 0;
	req[0].data_size = idx % 2 == 0 ? 0 : sizeof(name);
	TEST_note("%s: name query, data_size=%zu", propqueries[idx / 2],
		  req[0].data_size);
	ret = TEST_true(OSSL_PROVIDER_get_params(p, req));
	ret &= TEST_size_t_eq(req[0].return_size, strlen(name));
	ret &= TEST_ptr_null(req[0].data);
	return ret;
}

static int test_integer_buffer_bounds(int idx)
{
	union buffer {
		size_t size;
		int status;
		unsigned char bytes[sizeof(size_t) + sizeof(int)];
	} actual[3], expected[3];
	size_t width = idx == 0 ? sizeof(size_t) : sizeof(int);
	EVP_MD *md = NULL;
	int ret = 1;

	if (idx == 0 && !TEST_ptr(md = EVP_MD_fetch(libctx, "SHA2-256", PROPQ)))
		return 0;

	for (size_t capacity = 0; capacity <= width + 1; ++capacity) {
		OSSL_PARAM req[] = { OSSL_PARAM_END, OSSL_PARAM_END };
		int result;

		memset(actual, 0xa5, sizeof(actual));
		memset(expected, 0xa5, sizeof(expected));
		if (idx == 0) {
			req[0] = OSSL_PARAM_construct_size_t(
				OSSL_DIGEST_PARAM_SIZE, &actual[1].size);
			if (capacity == width)
				expected[1].size = 32;
		} else {
			req[0] =
				OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS,
							 &actual[1].status);
			if (capacity == width)
				expected[1].status = 1;
		}
		req[0].data_size = capacity;
		TEST_note("%s: integer buffer, data_size=%zu", req[0].key,
			  capacity);
		result = idx == 0 ? EVP_MD_get_params(md, req)
				  : OSSL_PROVIDER_get_params(prov, req);
		/* These helpers accept only native-width integer buffers. */
		ret &= TEST_int_eq(result, capacity == width);
		ret &= TEST_size_t_eq(req[0].return_size, width);
		ret &= TEST_size_t_eq(req[0].data_size, capacity);
		/* Guard storage keeps a broken native-width write in-bounds. */
		ret &= TEST_mem_eq(actual, sizeof(actual), expected,
				   sizeof(expected));
	}
	EVP_MD_free(md);
	return ret;
}

static const struct {
	const char *name;
	const char *key;
	const char *value;
	size_t data_size;
	int bufferless;
	unsigned int data_type;
} string_cases[] = {
	{ "query", "test-text", "abc", 0, 1, OSSL_PARAM_UTF8_STRING },
	{ "query with size", "test-text", "abc", 4, 1, OSSL_PARAM_UTF8_STRING },
	{ "empty query", "test-empty", "", 0, 1, OSSL_PARAM_UTF8_STRING },
	{ "empty, zero capacity", "test-empty", "", 0, 0,
	  OSSL_PARAM_UTF8_STRING },
	{ "empty with NUL", "test-empty", "", 1, 0, OSSL_PARAM_UTF8_STRING },
	{ "short buffer", "test-text", "abc", 2, 0, OSSL_PARAM_UTF8_STRING },
	{ "exact text length", "test-text", "abc", 3, 0,
	  OSSL_PARAM_UTF8_STRING },
	{ "room for NUL", "test-text", "abc", 4, 0, OSSL_PARAM_UTF8_STRING },
	{ "spare capacity", "test-text", "abc", 8, 0, OSSL_PARAM_UTF8_STRING },
	{ "wrong type", "test-text", "abc", 8, 0, OSSL_PARAM_OCTET_STRING },
};

static int test_utf8_string(int idx)
{
	unsigned char actual[8], expected[8];
	OSSL_PARAM req[] = { OSSL_PARAM_END, OSSL_PARAM_END };
	OSSL_PARAM reference;
	int expected_ret, ret;

	TEST_note("set_utf8_string: %s", string_cases[idx].name);
	memset(actual, 0xa5, sizeof(actual));
	memset(expected, 0xa5, sizeof(expected));
	/* Set size explicitly to avoid the constructor's strlen shortcut. */
	req[0] = OSSL_PARAM_construct_utf8_string(string_cases[idx].key, NULL,
						  0);
	req[0].data = string_cases[idx].bufferless ? NULL : actual;
	req[0].data_size = string_cases[idx].data_size;
	req[0].data_type = string_cases[idx].data_type;
	reference = req[0];
	reference.data = string_cases[idx].bufferless ? NULL : expected;

	expected_ret =
		OSSL_PARAM_set_utf8_string(&reference, string_cases[idx].value);
	/* The short-buffer and wrong-type control calls may queue errors. */
	ERR_clear_error();
	ret = TEST_int_eq(EVP_MD_get_params(params_md, req), expected_ret);
	/* A rejected type reports no size, as OpenSSL 3.5 and later do
	 * (commit 1dafff06ca6a, "Don't promise a non-zero return size in
	 * error cases"); older libcrypto still reports the text length there,
	 * so the reference value is not comparable for that case. */
	if (string_cases[idx].data_type == OSSL_PARAM_UTF8_STRING)
		ret &= TEST_size_t_eq(req[0].return_size,
				      reference.return_size);
	else
		ret &= TEST_size_t_eq(req[0].return_size, 0);
	/* Compare all bytes, including NUL and the untouched buffer tail. */
	ret &= TEST_mem_eq(actual, sizeof(actual), expected, sizeof(expected));
	return ret;
}

/* Optional setters must still be reachable when DUPCTX is omitted. */
static int test_ctx_setters(void)
{
	EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	const OSSL_PARAM *table, *entry;
	unsigned char out[EVP_MAX_MD_SIZE];
	unsigned int outl = 0;
	int value = 42, ret = 0;
	OSSL_PARAM params[] = { OSSL_PARAM_int("test-value", &value),
				OSSL_PARAM_END };

	if (!TEST_ptr(md = EVP_MD_fetch(libctx, "RUSTLE-PARAMS-TEST",
					"provider=rustle_params_test"))
	    || !TEST_ptr(ctx = EVP_MD_CTX_new())
	    || !TEST_ptr(table = EVP_MD_settable_ctx_params(md))
	    || !TEST_ptr(entry = OSSL_PARAM_locate_const(table, "test-value"))
	    || !TEST_uint_eq(entry->data_type, OSSL_PARAM_INTEGER))
		goto err;
	/* INIT and SET_CTX_PARAMS share the generated parameter handler. */
	if (!TEST_true(EVP_DigestInit_ex2(ctx, md, params))
	    || !TEST_true(EVP_DigestFinal_ex(ctx, out, &outl))
	    || !TEST_uint_eq(outl, 1) || !TEST_uint_eq(out[0], 42))
		goto err;
	value = 7;
	if (!TEST_true(EVP_DigestInit_ex2(ctx, md, NULL))
	    || !TEST_true(EVP_MD_CTX_set_params(ctx, params))
	    || !TEST_true(EVP_DigestFinal_ex(ctx, out, &outl))
	    || !TEST_uint_eq(outl, 1) || !TEST_uint_eq(out[0], 7))
		goto err;
	value = -1;
	if (!TEST_int_eq(EVP_MD_CTX_set_params(ctx, params), 0))
		goto err;
	ret = 1;
err:
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
	return ret;
}

/*
 * A context parameter this provider serves in both directions: the fixture
 * pairs its getter with its setter, as upstream does for every digest
 * context parameter it serves (SHAKE's xoflen/size, blake2's size).
 */
static int test_ctx_getters(void)
{
	EVP_MD_CTX *ctx = NULL;
	const OSSL_PARAM *table, *entry;
	int value = 42, readback = 0, ret = 0;
	OSSL_PARAM set[] = { OSSL_PARAM_int("test-value", &value),
			     OSSL_PARAM_END };
	OSSL_PARAM get[] = { OSSL_PARAM_int("test-value", &readback),
			     OSSL_PARAM_END };

	if (!TEST_ptr(ctx = EVP_MD_CTX_new())
	    || !TEST_ptr(table = EVP_MD_gettable_ctx_params(params_md))
	    || !TEST_ptr(entry = OSSL_PARAM_locate_const(table, "test-value"))
	    || !TEST_uint_eq(entry->data_type, OSSL_PARAM_INTEGER))
		goto err;

	/* The value set through INIT is the value read back. */
	if (!TEST_true(EVP_DigestInit_ex2(ctx, params_md, set))
	    || !TEST_ptr(EVP_MD_CTX_gettable_params(ctx))
	    || !TEST_true(EVP_MD_CTX_get_params(ctx, get))
	    || !TEST_int_eq(readback, 42)
	    || !TEST_size_t_eq(get[0].return_size, sizeof(int)))
		goto err;

	/* And so is the value set through SET_CTX_PARAMS afterwards. */
	value = 7;
	readback = 0;
	if (!TEST_true(EVP_MD_CTX_set_params(ctx, set))
	    || !TEST_true(EVP_MD_CTX_get_params(ctx, get))
	    || !TEST_int_eq(readback, 7))
		goto err;
	ret = 1;
err:
	EVP_MD_CTX_free(ctx);
	return ret;
}

/*
 * The bufferless query, an undescribed name, and a described name requested
 * as the wrong type. The middle case is what upstream's SHAKE128 does with
 * an unknown name alongside a known one: leave it alone and still succeed.
 */
static int test_ctx_getter_bounds(void)
{
	EVP_MD_CTX *ctx = NULL;
	int value = 42, readback = 0, spare = 123, ret = 0;
	size_t wrong_type = 0;
	OSSL_PARAM set[] = { OSSL_PARAM_int("test-value", &value),
			     OSSL_PARAM_END };
	OSSL_PARAM query[] = { OSSL_PARAM_int("test-value", NULL),
			       OSSL_PARAM_END };
	OSSL_PARAM mixed[] = { OSSL_PARAM_int("test-value", &readback),
			       OSSL_PARAM_int("no-such-param", &spare),
			       OSSL_PARAM_END };
	OSSL_PARAM mistyped[] = { OSSL_PARAM_size_t("test-value", &wrong_type),
				  OSSL_PARAM_END };

	if (!TEST_ptr(ctx = EVP_MD_CTX_new())
	    || !TEST_true(EVP_DigestInit_ex2(ctx, params_md, set)))
		goto err;

	/* Null data is a size query, reporting the native integer width. */
	query[0].data_size = 0;
	if (!TEST_true(EVP_MD_CTX_get_params(ctx, query))
	    || !TEST_size_t_eq(query[0].return_size, sizeof(int))
	    || !TEST_ptr_null(query[0].data))
		goto err;

	/* A name the descriptor table does not list stays untouched: its
	 * return_size keeps the OSSL_PARAM_UNMODIFIED the constructor set. */
	if (!TEST_true(EVP_MD_CTX_get_params(ctx, mixed))
	    || !TEST_int_eq(readback, 42) || !TEST_int_eq(spare, 123)
	    || !TEST_true(OSSL_PARAM_modified(&mixed[0]))
	    || !TEST_false(OSSL_PARAM_modified(&mixed[1])))
		goto err;

	/* A described name requested as the wrong type fails the whole call
	 * without writing, as the integer helpers do elsewhere. */
	if (!TEST_int_eq(EVP_MD_CTX_get_params(ctx, mistyped), 0)
	    || !TEST_size_t_eq(wrong_type, 0)
	    || !TEST_size_t_eq(mistyped[0].return_size, 0))
		goto err;
	ret = 1;
err:
	EVP_MD_CTX_free(ctx);
	return ret;
}

int setup_tests(void)
{
	if (!bc_rust_load(test_argc > 1 ? test_argv[1] : NULL, &libctx, &prov))
		return 0;
	if (!TEST_ptr(default_prov = OSSL_PROVIDER_load(libctx, "default")))
		return 0;
	if (!TEST_ptr(params_prov =
			      OSSL_PROVIDER_load(libctx, PARAMS_PROVIDER_PATH))
	    || !TEST_ptr(params_md =
				 EVP_MD_fetch(libctx, "RUSTLE-PARAMS-TEST",
					      "provider=rustle_params_test")))
		return 0;

	ADD_ALL_TESTS(test_size_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_status_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_name_query, 2 * ARRAY_SIZE(propqueries));
	ADD_ALL_TESTS(test_integer_buffer_bounds, 2);
	ADD_ALL_TESTS(test_utf8_string, ARRAY_SIZE(string_cases));
	ADD_TEST(test_ctx_setters);
	ADD_TEST(test_ctx_getters);
	ADD_TEST(test_ctx_getter_bounds);
	return 1;
}

void cleanup_tests(void)
{
	EVP_MD_free(params_md);
	OSSL_PROVIDER_unload(params_prov);
	OSSL_PROVIDER_unload(default_prov);
	bc_rust_unload(libctx, prov);
}
