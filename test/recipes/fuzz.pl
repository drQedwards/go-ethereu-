# Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use File::Basename;
use OpenSSL::Glob;
use OpenSSL::Test qw/:DEFAULT srctop_dir
                      memfail_schedule memfail_env
                      memfail_count memfail_n_for_level/;

sub fuzz_ok {
    my ($f, %opts) = @_;

    my $d = srctop_dir('fuzz', 'corpora', $f);
    my $level = $opts{level} // 3;

    SKIP: {
        skip "No directory $d", 1 unless -d $d;

        my $spec = $ENV{OSSL_FUZZ_TEST_MEMFAIL};
        if (!defined $spec || $spec eq '0') {
            ok(run(fuzz(["$f-test", $d])), "Fuzzing $f");
        } else {
            fuzz_memfail_ok($f, $d, $level);
        }
    }
}

sub fuzz_memfail_ok {
    my ($fuzzer, $dir, $level) = @_;

    my @files = sort grep { -f $_ } glob("$dir/*");

    subtest "Fuzzing $fuzzer with memfail" => sub {
        plan tests => scalar(@files) + 1;
        my $file_idx = 0;
        my $tested = 0;

        for my $file (@files) {
            my $basename = basename($file);

            my ($skip, $total) = memfail_count(fuzz(["$fuzzer-test", $file]));

            my $n = $total > 0 ? memfail_n_for_level($level, $total) : 0;
            my @indices = $n > 0 ? memfail_schedule($total, $n, $file_idx) : ();

            if (!@indices) {
                # Still run the file once normally so it appears in the output
                ok(run(fuzz(["$fuzzer-test", $file])),
                    "Fuzzing $basename (no memfail)");
            } else {
                $tested++;
                subtest "memfail $basename ($total allocs, $n points)" => sub {
                    plan tests => scalar @indices;
                    for my $idx (@indices) {
                        local $ENV{OPENSSL_MALLOC_FAILURES}
                            = memfail_env($skip, $idx);
                        ok(run(fuzz(["$fuzzer-test", $file])),
                           "fail at alloc $idx/$total");
                    }
                };
            }

            $file_idx++;
        }

        ok($tested > 0, "memfail tested $tested corpus files");
    };
}

1;
