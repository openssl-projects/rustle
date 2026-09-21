/* Copyright The OpenSSL Project Authors. All Rights Reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The test driver: main(), test registration, TAP output, assertions.
 * See ../testutil.h for the API a test file uses.
 *
 * Build the OpenSSL error-queue support out with -DTEST_NO_ERR to get a
 * driver that does not need libcrypto at all.
 */
#include "../testutil.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TEST_NO_ERR
# include <openssl/err.h>
#endif

#if defined(__APPLE__) || defined(__linux__)
/* ASan reads this before main; ASAN_OPTIONS overrides these defaults. */
const char *__asan_default_options(void)
{
	return "detect_leaks=1";
}
#endif

#ifndef MAX_TESTS
# define MAX_TESTS 1024
#endif
/* Bytes of a mismatching buffer to hex-dump before giving up. */
#define MEM_DUMP_MAX 64

struct test_info {
	const char *name;
	int (*fn)(void);
	int (*param_fn)(int idx);
	int num; /* -1 for a plain test */
	int subtest;
};

static struct test_info all_tests[MAX_TESTS];
static int num_tests;
static int num_test_cases;

static int show_list;
static int single_test = -1;
static int single_iter = -1;
static int tap_indent;

int test_argc;
char **test_argv;

/* argv[0], for the driver's own error messages. */
static const char *prog = "test";

/* Weak defaults; a test file may define either to override. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak)) int global_init(void)
{
	return 1;
}
__attribute__((weak)) void cleanup_tests(void)
{
}
#endif

/* ------------------------------------------------------------------ */
/* Output                                                             */
/* ------------------------------------------------------------------ */

static void tap_out(const char *fmt, ...)
{
	va_list ap;

	fprintf(stdout, "%*s", tap_indent, "");
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fflush(stdout);
}

/* Diagnostics go to stderr, TAP-commented so they survive a harness. */
static void diag_va(const char *fmt, va_list ap)
{
	fflush(stdout);
	fprintf(stderr, "%*s# ", tap_indent, "");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	fflush(stderr);
}

static void diag(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	diag_va(fmt, ap);
	va_end(ap);
}

void test_diag(const char *prefix, const char *file, int line, const char *fmt,
	       ...)
{
	va_list ap;

	fflush(stdout);
	fprintf(stderr, "%*s# %s: ", tap_indent, "", prefix);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (file != NULL)
		fprintf(stderr, " @ %s:%d", file, line);
	fputc('\n', stderr);
	fflush(stderr);
}

void test_note(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	diag_va(fmt, ap);
	va_end(ap);
}

void test_perror(const char *s)
{
	diag("%s: %s", s, strerror(errno));
}

#ifndef TEST_NO_ERR
static int err_cb(const char *str, size_t len, void *u)
{
	(void)u;
	fflush(stdout);
	fprintf(stderr, "%*s# %.*s", tap_indent, "", (int)len, str);
	if (len == 0 || str[len - 1] != '\n')
		fputc('\n', stderr);
	return 1;
}

void test_openssl_errors(void)
{
	ERR_print_errors_cb(err_cb, NULL);
	ERR_clear_error();
}
#else
void test_openssl_errors(void)
{
}
#endif

/* ------------------------------------------------------------------ */
/* Assertions                                                         */
/* ------------------------------------------------------------------ */

/*
 * Failure message prefix, byte for byte as OpenSSL's
 * test/testutil/tests.c writes it: a `prefix` *replaces* the default
 * "ERROR", a NULL `op` prints nothing, and a NULL left/right falls back to
 * printing `op` alone. Only the leading TAP "# " and indent are ours —
 * diagnostics on this driver's stderr have to stay valid TAP comments.
 */
static void test_fail_message_prefix(const char *prefix, const char *file,
				     int line, const char *type,
				     const char *left, const char *right,
				     const char *op)
{
	fflush(stdout);
	fprintf(stderr, "%*s# %s: ", tap_indent, "",
		prefix != NULL ? prefix : "ERROR");
	if (type)
		fprintf(stderr, "(%s) ", type);
	if (op != NULL) {
		if (left != NULL && right != NULL)
			fprintf(stderr, "'%s %s %s' failed", left, op, right);
		else
			fprintf(stderr, "'%s'", op);
	}
	if (file != NULL)
		fprintf(stderr, " @ %s:%d", file, line);
	fprintf(stderr, "\n");
}

static void test_fail_message_va(const char *prefix, const char *file, int line,
				 const char *type, const char *left,
				 const char *right, const char *op,
				 const char *fmt, va_list ap)
{
	test_fail_message_prefix(prefix, file, line, type, left, right, op);
	if (fmt != NULL) {
		fprintf(stderr, "%*s#   ", tap_indent, "");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	fflush(stderr);
}

static void test_fail_message(const char *prefix, const char *file, int line,
			      const char *type, const char *left,
			      const char *right, const char *op,
			      const char *fmt, ...) TEST_PRINTF_FORMAT(8, 9);

static void test_fail_message(const char *prefix, const char *file, int line,
			      const char *type, const char *left,
			      const char *right, const char *op,
			      const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	test_fail_message_va(prefix, file, line, type, left, right, op, fmt,
			     ap);
	va_end(ap);
}

/*
 * Define some comparisons between pairs of various types.
 * These functions return 1 if the test is true.
 * Otherwise, they return 0 and pretty-print diagnostics.
 *
 * In each case the functions produced are:
 *  int test_name_eq(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ne(const type t1, const type t2, const char *desc, ...);
 *  int test_name_lt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_le(const type t1, const type t2, const char *desc, ...);
 *  int test_name_gt(const type t1, const type t2, const char *desc, ...);
 *  int test_name_ge(const type t1, const type t2, const char *desc, ...);
 *
 * The t1 and t2 arguments are to be compared for equality, inequality,
 * less than, less than or equal to, greater than and greater than or
 * equal to respectively.  If the specified condition holds, the functions
 * return 1.  If the condition does not hold, the functions print a diagnostic
 * message and return 0.
 *
 * The desc argument is a printf format string followed by its arguments and
 * this is included in the output if the condition being tested for is false.
 */
#define DEFINE_COMPARISON(type, name, opname, op, fmt, cast)                   \
	int test_##name##_##opname(const char *file, int line, const char *s1, \
				   const char *s2, const type t1,              \
				   const type t2)                              \
	{                                                                      \
		if (t1 op t2)                                                  \
			return 1;                                              \
		test_fail_message(NULL, file, line, #type, s1, s2, #op,        \
				  "[" fmt "] compared to [" fmt "]", (cast)t1, \
				  (cast)t2);                                   \
		return 0;                                                      \
	}

#define DEFINE_COMPARISONS(type, name, fmt, cast)                              \
	DEFINE_COMPARISON(type, name, eq, ==, fmt, cast)                       \
	DEFINE_COMPARISON(type, name, ne, !=, fmt, cast)                       \
	DEFINE_COMPARISON(type, name, lt, <, fmt, cast)                        \
	DEFINE_COMPARISON(type, name, le, <=, fmt, cast)                       \
	DEFINE_COMPARISON(type, name, gt, >, fmt, cast)                        \
	DEFINE_COMPARISON(type, name, ge, >=, fmt, cast)

DEFINE_COMPARISONS(int, int, "%d", int)
DEFINE_COMPARISONS(unsigned int, uint, "%u", unsigned int)
DEFINE_COMPARISONS(char, char, "%c", char)
DEFINE_COMPARISONS(unsigned char, uchar, "%u", unsigned char)
DEFINE_COMPARISONS(long, long, "%ld", long)
DEFINE_COMPARISONS(unsigned long, ulong, "%lu", unsigned long)
DEFINE_COMPARISONS(int64_t, int64_t, "%lld", long long)
DEFINE_COMPARISONS(uint64_t, uint64_t, "%llu", unsigned long long)
/*
 * Defined unconditionally, like OpenSSL: only the declaration and the
 * TEST_size_t_* macros sit behind TESTUTIL_NO_size_t_COMPARISON, so opting
 * out in a test file cannot change what the driver object exports.
 */
DEFINE_COMPARISONS(size_t, size_t, "%zu", size_t)
DEFINE_COMPARISONS(double, double, "%g", double)

DEFINE_COMPARISON(void *, ptr, eq, ==, "%p", const void *)
DEFINE_COMPARISON(void *, ptr, ne, !=, "%p", const void *)

int test_ptr_null(const char *file, int line, const char *s, const void *p)
{
	if (p == NULL)
		return 1;
	test_fail_message(NULL, file, line, "ptr", s, "NULL", "==", "%p", p);
	return 0;
}

int test_ptr(const char *file, int line, const char *s, const void *p)
{
	if (p != NULL)
		return 1;
	test_fail_message(NULL, file, line, "ptr", s, "NULL", "!=", "%p", p);
	return 0;
}

int test_true(const char *file, int line, const char *s, int b)
{
	if (b)
		return 1;
	test_fail_message(NULL, file, line, "bool", s, "true", "==", "false");
	return 0;
}

int test_false(const char *file, int line, const char *s, int b)
{
	if (!b)
		return 1;
	test_fail_message(NULL, file, line, "bool", s, "false", "==", "true");
	return 0;
}

/*
 * strnlen(3) is POSIX-2008, not C99, so provide it locally rather than rely
 * on the host declaring it under -std=c99.
 */
static size_t test_strnlen(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n && s[i] != '\0'; i++)
		continue;
	return i;
}

/*
 * Upstream's signature. It reports through diag() instead of porting
 * OpenSSL's chunked column differ, which is a good deal more code than the
 * rest of this driver put together; the lengths and the first differing
 * offset are what actually gets used.
 */
static void test_fail_string_message(const char *prefix, const char *file,
				     int line, const char *type,
				     const char *left, const char *right,
				     const char *op, const char *m1, size_t l1,
				     const char *m2, size_t l2)
{
	size_t i, j;

	test_fail_message_prefix(prefix, file, line, type, left, right, op);
	if (m1 == NULL)
		diag("  left : NULL");
	else
		diag("  left : (%zu chars) \"%.*s\"", l1, (int)l1, m1);
	if (m2 == NULL)
		diag("  right: NULL");
	else
		diag("  right: (%zu chars) \"%.*s\"", l2, (int)l2, m2);

	if (m1 == NULL || m2 == NULL)
		return;
	j = l1 < l2 ? l1 : l2;
	for (i = 0; i < j; i++)
		if (m1[i] != m2[i]) {
			diag("  first difference at char %zu: '%c' != '%c'", i,
			     m1[i], m2[i]);
			return;
		}
	if (l1 != l2)
		diag("  common prefix of %zu chars, lengths differ", j);
}

int test_str_eq(const char *file, int line, const char *st1, const char *st2,
		const char *s1, const char *s2)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL || s2 == NULL || strcmp(s1, s2) != 0) {
		test_fail_string_message(NULL, file, line, "string", st1, st2,
					 "==", s1, s1 == NULL ? 0 : strlen(s1),
					 s2, s2 == NULL ? 0 : strlen(s2));
		return 0;
	}
	return 1;
}

int test_str_ne(const char *file, int line, const char *st1, const char *st2,
		const char *s1, const char *s2)
{
	if ((s1 == NULL) ^ (s2 == NULL))
		return 1;
	if (s1 == NULL || strcmp(s1, s2) == 0) {
		test_fail_string_message(NULL, file, line, "string", st1, st2,
					 "!=", s1, s1 == NULL ? 0 : strlen(s1),
					 s2, s2 == NULL ? 0 : strlen(s2));
		return 0;
	}
	return 1;
}

int test_strn_eq(const char *file, int line, const char *st1, const char *st2,
		 const char *s1, const char *s2, size_t n)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (s1 == NULL || s2 == NULL || strncmp(s1, s2, n) != 0) {
		test_fail_string_message(NULL, file, line, "string", st1, st2,
					 "==", s1,
					 s1 == NULL ? 0 : test_strnlen(s1, n),
					 s2,
					 s2 == NULL ? 0 : test_strnlen(s2, n));
		return 0;
	}
	return 1;
}

int test_strn_ne(const char *file, int line, const char *st1, const char *st2,
		 const char *s1, const char *s2, size_t n)
{
	if ((s1 == NULL) ^ (s2 == NULL))
		return 1;
	if (s1 == NULL || strncmp(s1, s2, n) == 0) {
		test_fail_string_message(NULL, file, line, "string", st1, st2,
					 "!=", s1,
					 s1 == NULL ? 0 : test_strnlen(s1, n),
					 s2,
					 s2 == NULL ? 0 : test_strnlen(s2, n));
		return 0;
	}
	return 1;
}

/* Hex dump for the memory comparison's diagnostics. */
static void hexdiag(const char *label, const unsigned char *p, size_t n)
{
	size_t i, shown = n > MEM_DUMP_MAX ? MEM_DUMP_MAX : n;
	char buf[MEM_DUMP_MAX * 2 + 1];

	if (p == NULL) {
		diag("  %s: NULL", label);
		return;
	}
	for (i = 0; i < shown; i++)
		snprintf(buf + i * 2, 3, "%02x", p[i]);
	buf[shown * 2] = '\0';
	diag("  %s: (%zu bytes) %s%s", label, n, buf, shown < n ? "..." : "");
}

/*
 * Upstream's signature (unsigned char, as its test_fail_memory_message
 * takes). Reports through hexdiag() rather than porting OpenSSL's chunked
 * column differ.
 */
static void test_fail_memory_message(const char *prefix, const char *file,
				     int line, const char *type,
				     const char *left, const char *right,
				     const char *op, const unsigned char *m1,
				     size_t l1, const unsigned char *m2,
				     size_t l2)
{
	size_t i, j;

	test_fail_message_prefix(prefix, file, line, type, left, right, op);
	hexdiag("left ", m1, l1);
	hexdiag("right", m2, l2);

	if (m1 == NULL || m2 == NULL)
		return;
	j = l1 < l2 ? l1 : l2;
	for (i = 0; i < j; i++)
		if (m1[i] != m2[i]) {
			diag("  first difference at byte %zu: %02x != %02x", i,
			     m1[i], m2[i]);
			return;
		}
	if (l1 != l2)
		diag("  common prefix of %zu bytes, lengths differ", j);
}

int test_mem_eq(const char *file, int line, const char *st1, const char *st2,
		const void *s1, size_t n1, const void *s2, size_t n2)
{
	if (s1 == NULL && s2 == NULL)
		return 1;
	if (n1 != n2 || s1 == NULL || s2 == NULL || memcmp(s1, s2, n1) != 0) {
		test_fail_memory_message(NULL, file, line, "memory", st1, st2,
					 "==", s1, n1, s2, n2);
		return 0;
	}
	return 1;
}

int test_mem_ne(const char *file, int line, const char *st1, const char *st2,
		const void *s1, size_t n1, const void *s2, size_t n2)
{
	if ((s1 == NULL) ^ (s2 == NULL))
		return 1;
	if (n1 != n2)
		return 1;
	if (s1 == NULL || memcmp(s1, s2, n1) == 0) {
		test_fail_memory_message(NULL, file, line, "memory", st1, st2,
					 "!=", s1, n1, s2, n2);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------ */
/* Registration                                                       */
/* ------------------------------------------------------------------ */

static void register_test(const char *name)
{
	if (num_tests == MAX_TESTS) {
		fprintf(stderr, "%s: too many tests (max %d)\n", prog,
			MAX_TESTS);
		exit(EXIT_FAILURE);
	}
	all_tests[num_tests].name = name;
	all_tests[num_tests].num = -1;
}

void add_test(const char *name, int (*fn)(void))
{
	register_test(name);
	all_tests[num_tests].fn = fn;
	num_tests++;
	num_test_cases++;
}

void add_all_tests(const char *name, int (*fn)(int idx), int num, int subtest)
{
	register_test(name);
	all_tests[num_tests].param_fn = fn;
	all_tests[num_tests].num = num;
	all_tests[num_tests].subtest = subtest;
	num_tests++;
	num_test_cases += subtest ? 1 : num;
}

/* ------------------------------------------------------------------ */
/* Running                                                            */
/* ------------------------------------------------------------------ */

static void verdict(int v, int n, const char *name, int idx)
{
	const char *ok = v == 0 ? "not ok" : "ok";

	fflush(stderr);
	if (idx >= 0)
		tap_out("%s %d - iteration %d", ok, n, idx + 1);
	else
		tap_out("%s %d - %s", ok, n, name);
	if (v == TEST_SKIP_CODE)
		fputs(" # skipped", stdout);
	fputc('\n', stdout);
	fflush(stdout);
}

/* Run one test body with the error queue cleared around it. */
static int run_one(int (*fn)(void), int (*param_fn)(int), int idx)
{
	int v;

#ifndef TEST_NO_ERR
	ERR_clear_error();
#endif
	v = param_fn != NULL ? param_fn(idx) : fn();
	if (v == 0)
		test_openssl_errors();
#ifndef TEST_NO_ERR
	else
		ERR_clear_error();
#endif
	return v;
}

static void usage(const char *test_prog_name)
{
	fprintf(stderr,
		"usage: %s [-list] [-test N] [-iter N] [test args...]\n"
		"  -list     list the registered tests and exit\n"
		"  -test N   run only test N (1-based, as shown by -list)\n"
		"  -iter N   run only iteration N of a parameterised test\n",
		test_prog_name);
}

/* Consume the driver's own options; leave the rest in test_argc/test_argv. */
static int parse_options(int argc, char **argv)
{
	int i, keep = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-list") == 0) {
			show_list = 1;
		} else if (strcmp(argv[i], "-test") == 0 && i + 1 < argc) {
			single_test = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-iter") == 0 && i + 1 < argc) {
			single_iter = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-help") == 0
			   || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			argv[keep++] = argv[i];
		}
	}
	test_argc = keep;
	test_argv = argv;
	return 1;
}

static int run_tests(const char *test_prog_name)
{
	int i, j, num_failed = 0, case_no = 0;

	if (num_tests == 0) {
		tap_out("1..0 # Skipped: %s\n", test_prog_name);
		return EXIT_SUCCESS;
	}
	if (show_list) {
		for (i = 0; i < num_tests; i++) {
			if (all_tests[i].num != -1)
				tap_out("%d - %s (1..%d)\n", i + 1,
					all_tests[i].name, all_tests[i].num);
			else
				tap_out("%d - %s\n", i + 1, all_tests[i].name);
		}
		return EXIT_SUCCESS;
	}
	if (single_test == -1 && single_iter == -1)
		tap_out("1..%d\n", num_test_cases);

	for (i = 0; i < num_tests; i++) {
		struct test_info *t = &all_tests[i];
		int v;

		if (single_test != -1 && i + 1 != single_test)
			continue;

		if (t->num == -1) {
			v = run_one(t->fn, NULL, -1);
			verdict(v, ++case_no, t->name, -1);
			if (v == 0)
				num_failed++;
			continue;
		}

		/* Parameterised: each iteration is a case or a subtest. */
		if (t->subtest) {
			tap_out("# Subtest: %s\n", t->name);
			tap_indent += 4;
			if (single_iter == -1)
				tap_out("1..%d\n", t->num);
		}
		v = TEST_SKIP_CODE;
		for (j = 0; j < t->num; j++) {
			int iv;

			if (single_iter != -1 && j + 1 != single_iter)
				continue;
			iv = run_one(NULL, t->param_fn, j);
			if (t->subtest) {
				verdict(iv, j + 1, t->name, j);
			} else {
				verdict(iv, ++case_no, t->name, j);
				if (iv == 0)
					num_failed++;
			}
			if (iv == 0)
				v = 0;
			else if (v != 0 && iv != TEST_SKIP_CODE)
				v = 1;
		}
		if (t->subtest) {
			tap_indent -= 4;
			verdict(v, ++case_no, t->name, -1);
			if (v == 0)
				num_failed++;
		}
	}
	if (num_failed != 0)
		diag("%d test%s failed", num_failed,
		     num_failed == 1 ? "" : "s");
	return num_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE, setup_res;

	prog = argv[0];
	if (!parse_options(argc, argv))
		return EXIT_FAILURE;

	if (!global_init()) {
		fprintf(stderr, "%s: global_init() failed\n", prog);
		return EXIT_FAILURE;
	}

	setup_res = setup_tests();
	if (setup_res > 0) {
		ret = run_tests(argv[0]);
		cleanup_tests();
	} else {
		if (setup_res == 0)
			usage(argv[0]);
		else
			fprintf(stderr, "%s: setup_tests() failed\n", prog);
		cleanup_tests();
	}
	return ret;
}
