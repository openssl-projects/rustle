#! /usr/bin/env perl
# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../perl";
use Rustle::Test;

run_test_program('evp_xof_test');
