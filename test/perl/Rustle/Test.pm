# Copyright The OpenSSL Project Authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

=head1 NAME

Rustle::Test - locate and run a compiled test program from a prove recipe

=head1 DESCRIPTION

The programs under F<test/> emit TAP themselves, so a recipe has nothing to
translate: it C<exec>s the program and the driver's output I<is> the recipe's
output. What a recipe cannot work out for itself is where the program and the
provider module ended up, which is all this module answers.

The root F<Makefile> passes both in the environment, so the guesses here only
matter when a recipe is run by hand:

  BC_RUST_TEST_DIR   directory holding the compiled test programs
  BC_RUST_MODULE     full path to the provider cdylib
  BC_RUST_PROFILE    cargo profile to look under (default: debug)

=cut

package Rustle::Test;

use strict;
use warnings;

use Exporter qw(import);
use File::Spec;
use FindBin;

our @EXPORT = qw(run_test_program test_program_path module_path);

# FindBin keys off $0, so this is the running recipe's directory however the
# recipe was invoked -- by prove, or from any working directory by hand.
sub test_dir
{
	return $ENV{BC_RUST_TEST_DIR}
		if defined $ENV{BC_RUST_TEST_DIR} && $ENV{BC_RUST_TEST_DIR} ne '';
	# <test>/recipes/NN-test_foo.t -> <test>
	return File::Spec->catdir($FindBin::Bin, File::Spec->updir);
}

# <test> -> the workspace root, where cargo keeps target/.
sub top_dir
{
	return File::Spec->catdir(test_dir(), File::Spec->updir);
}

# Rust names a cdylib the platform's way; Windows has no "lib" prefix. Kept
# in step with the same three cases in the root Makefile.
sub module_file
{
	return 'libbc_rust.dylib' if $^O eq 'darwin';
	return 'bc_rust.dll' if $^O =~ /^(?:MSWin32|msys|cygwin)$/;
	# Linux, the BSDs, and anything else ELF.
	return 'libbc_rust.so';
}

sub exe_ext
{
	return $^O =~ /^(?:MSWin32|msys|cygwin)$/ ? '.exe' : '';
}

sub module_path
{
	return $ENV{BC_RUST_MODULE}
		if defined $ENV{BC_RUST_MODULE} && $ENV{BC_RUST_MODULE} ne '';

	my $profile = $ENV{BC_RUST_PROFILE} || 'debug';
	return File::Spec->catfile(top_dir(), 'target', $profile,
				   module_file());
}

sub test_program_path
{
	my ($name) = @_;

	return File::Spec->catfile(test_dir(), $name . exe_ext());
}

# TAP's own way to give up on a whole file. Better than exiting without a
# plan, which a harness can only report as a crash.
sub bail_out
{
	my ($why) = @_;

	print "Bail out!  $why\n";
	exit 1;
}

=head2 run_test_program($name, @args)

Replaces this process with the test program C<$name>, passing it the module
path (and any C<@args>, which the driver forwards to the test as
C<test_argv>). Does not return.

=cut

sub run_test_program
{
	my ($name, @args) = @_;
	my $bin = test_program_path($name);
	my $module = module_path();

	bail_out("$bin is not executable; run `make` first")
		unless -x $bin;
	bail_out("$module does not exist; run `make module` first")
		unless -f $module;

	# exec, not system: the program's TAP becomes this recipe's TAP and its
	# exit status becomes the recipe's status. Nothing to forward, and no
	# risk of a wrapper's own output landing in the stream.
	exec($bin, $module, @args)
		or bail_out("could not run $bin: $!");
}

1;
