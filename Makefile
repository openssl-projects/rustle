# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Top-level entry point.
#
#   make            build both rustle configurations, the module, and C tests
#   make test       the two test suites: cargo's, and the C one under prove
#   make c-test     just the C suite, under the TAP harness
#   make check      everything a change has to pass before it is done
#   make help       list the targets
#
#   make OPENSSL_ROOT_DIR=/path/to/openssl test
#   make PROFILE=release c-test
#   make PROVE_FLAGS=-v c-test

CARGO  ?= cargo
MDBOOK ?= mdbook
CLANG_FORMAT ?= clang-format
CC ?= cc
PKGCONF ?= pkg-config
PROVE ?= prove
PROVE_FLAGS ?=

C_FORMAT_SRCS := $(shell find test -type f \( -name '*.c' -o -name '*.h' \) -print)

# Select libcrypto from a configured OpenSSL build tree for the C tests.
ifneq ($(strip $(OPENSSL_ROOT_DIR)),)
  OPENSSL_ROOT := $(abspath $(patsubst ~/%,$(HOME)/%,$(OPENSSL_ROOT_DIR)))
  OPENSSL_PKG_CONFIG_ENV := PKG_CONFIG_PATH='$(OPENSSL_ROOT)'
endif

# Cargo calls the debug profile "dev", but writes its artifacts to target/debug.
PROFILE ?= debug
ifeq ($(PROFILE),debug)
  override CARGO_PROFILE := dev
else ifeq ($(PROFILE),release)
  override CARGO_PROFILE := release
else
  $(error Unsupported PROFILE '$(PROFILE)'; use debug or release)
endif

# Keep clean/help and Rust-only targets independent of pkg-config.
OSSL_CFLAGS = $(shell $(OPENSSL_PKG_CONFIG_ENV) $(PKGCONF) --cflags libcrypto)
OSSL_LIBS = $(shell $(OPENSSL_PKG_CONFIG_ENV) $(PKGCONF) --libs libcrypto)
OSSL_LIBDIR = $(shell $(OPENSSL_PKG_CONFIG_ENV) $(PKGCONF) --variable=libdir libcrypto)

MODULE_DIR ?= $(abspath target/$(PROFILE))
CFLAGS ?= -O2 -g
# Keep project flags separate so command-line CFLAGS cannot discard them.
TEST_CPPFLAGS = -DDEFAULT_MODULE_DIR=\"$(MODULE_DIR)\" -Itest $(OSSL_CFLAGS)
TEST_CFLAGS := -Wall -Wextra -Wno-unused-parameter -Wshadow -pedantic -std=c99

# Rust names the cdylib the platform's way; Windows has no "lib" prefix.
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  MODULE := libbc_rust.dylib
else ifneq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME)))
  MODULE := bc_rust.dll
  EXE := .exe
else
  MODULE := libbc_rust.so
endif

# Test binaries locate libcrypto without runtime environment variables.
ifeq (,$(filter MINGW% MSYS% CYGWIN%,$(UNAME)))
  RPATH_LDFLAGS = -Wl,-rpath,$(OSSL_LIBDIR)
endif

COMMON_SRCS := test/testutil/driver.c test/testutil/provider.c
TEST_SRCS := test/provider_test.c test/evp_md_test.c test/params_test.c
TESTS := $(TEST_SRCS:%.c=%$(EXE))
SRCS := $(TEST_SRCS) $(COMMON_SRCS)
OBJS := $(SRCS:.c=.o)
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
RECIPES := $(sort $(wildcard test/recipes/*.t))

.PHONY: all build build-no-std build-std module build-test \
	params-provider run test c-test cargo-test check fmt rust-fmt c-fmt fmt-check \
	rust-fmt-check c-fmt-check clippy docs clean help check-libcrypto FORCE

all: build

# ------------------------------------------------------------------ #
# Building                                                           #
# ------------------------------------------------------------------ #

# rustle has to compile in both of its configurations, and the no_std one is
# the half that breaks silently: bc-rust-provider pulls in std, so building
# only the module never reports that rustle stopped being no_std-clean.
build: build-no-std build-std module build-test

build-no-std:
	$(CARGO) build -p rustle --no-default-features --features abort --profile $(CARGO_PROFILE)

build-std:
	$(CARGO) build -p rustle --features std --profile $(CARGO_PROFILE)

module:
	$(CARGO) build -p bc-rust-provider --profile $(CARGO_PROFILE)

build-test: $(TESTS)

# The C suite is small: rebuild rather than track headers and configuration.
$(OBJS): FORCE | check-libcrypto

check-libcrypto:
	$(OPENSSL_PKG_CONFIG_ENV) $(PKGCONF) --print-errors --exists libcrypto

# Compile separately so compilation-database tools record each source.
test/%.o: test/%.c
	$(CC) $(CPPFLAGS) $(TEST_CPPFLAGS) $(TEST_CFLAGS) $(CFLAGS) -c -o $@ $<

# The inline-string setter uses a test-only provider.
test/params_test.o: TEST_CPPFLAGS += -DPARAMS_PROVIDER_PATH=\"$(abspath $(MODULE_DIR))/examples/$(subst bc_rust,params_provider,$(MODULE))\"
test/params_test$(EXE): | params-provider

params-provider:
	$(CARGO) build -p rustle --example params_provider --features std --profile $(CARGO_PROFILE)

$(TESTS): %$(EXE): %.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(OSSL_LIBS) $(LDLIBS) $(RPATH_LDFLAGS)
ifeq ($(UNAME),Darwin)
	@crypto_install_name=$$(otool -L '$@' \
		| awk '/libcrypto.*[.]dylib/ { print $$1; exit }'); \
	case "$$crypto_install_name" in \
	/*) install_name_tool -change "$$crypto_install_name" \
		"@rpath/$$(basename "$$crypto_install_name")" '$@' ;; \
	esac
endif

# ------------------------------------------------------------------ #
# Testing                                                            #
# ------------------------------------------------------------------ #

# Rust tests and doctests, plus C tests through libcrypto's EVP API.
test: cargo-test c-test

# The C suite under prove: one recipe per test program in test/recipes/.
c-test: build-test module
	BC_RUST_TEST_DIR='$(abspath test)' \
	BC_RUST_MODULE='$(abspath $(MODULE_DIR)/$(MODULE))' \
	$(PROVE) $(PROVE_FLAGS) $(RECIPES)

# Raw TAP without the harness; individual programs also take -list/-test/-iter.
run: build-test module
	for t in $(TESTS); do ./$$t '$(abspath $(MODULE_DIR)/$(MODULE))' || exit 1; done

cargo-test:
	$(CARGO) test --profile $(CARGO_PROFILE)

# The full gate: both configurations build, formatting is clean, both suites
# pass.
check: build fmt-check test

# ------------------------------------------------------------------ #
# Housekeeping                                                       #
# ------------------------------------------------------------------ #

fmt: rust-fmt c-fmt

rust-fmt:
	$(CARGO) fmt

c-fmt:
	$(CLANG_FORMAT) --style=file -i $(C_FORMAT_SRCS)

fmt-check: rust-fmt-check c-fmt-check

rust-fmt-check:
	$(CARGO) fmt --check

c-fmt-check:
	$(CLANG_FORMAT) --style=file --dry-run --Werror $(C_FORMAT_SRCS)

clippy:
	$(CARGO) clippy --all-targets --profile $(CARGO_PROFILE)

docs:
	$(MDBOOK) build docs

clean:
	$(CARGO) clean
	rm -f $(TESTS) $(OBJS)
	rm -rf $(TESTS:%=%.dSYM)

help:
	@printf '%s\n' \
	'Targets:' \
	'  all            build (the default)' \
	'  build          both rustle configurations, the module, and C tests' \
	'  build-no-std   rustle without std, with its panic handler' \
	'  build-std      rustle with std' \
	'  module         the loadable provider cdylib' \
	'  build-test     build the C test programs without running them' \
	'  test/<name>    build one test program by name, e.g. test/evp_md_test' \
	'' \
	'  test           cargo-test and c-test' \
	'  c-test         the C suite under the TAP harness' \
	'  run            the C suite directly, with raw TAP output' \
	'  cargo-test     Rust tests and doctests' \
	'  check          build, fmt-check, test' \
	'' \
	'  fmt            format Rust and C sources' \
	'  rust-fmt       cargo fmt' \
	'  c-fmt          clang-format -i' \
	'  fmt-check      check Rust and C formatting' \
	'  rust-fmt-check cargo fmt --check' \
	'  c-fmt-check    clang-format --dry-run --Werror' \
	'  clippy         cargo clippy --all-targets' \
	'  docs           mdbook build docs' \
	'  clean          cargo clean and drop the C build artifacts' \
	'' \
	'Variables: PROFILE (debug|release), PROVE_FLAGS, CARGO, MDBOOK,' \
	'CLANG_FORMAT, OPENSSL_ROOT_DIR, CC, PKGCONF, PROVE,' \
	'CPPFLAGS, CFLAGS, LDFLAGS, LDLIBS'

FORCE:
