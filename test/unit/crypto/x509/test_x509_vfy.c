/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include "crypto/evp.h"
#include "crypto/x509.h"
#include "crypto/x509/x509_local.h"

/* wraps */

void __wrap_ERR_set_error(int lib, int reason, const char *fmt, ...);
int __wrap_X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
int __wrap_ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);
int __wrap_ASN1_OCTET_STRING_cmp(
    const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING *b);
int __wrap_X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
X509_EXTENSION *__wrap_X509_CRL_get_ext(const X509_CRL *x, int loc);
ASN1_OCTET_STRING *__wrap_X509_EXTENSION_get_data(const X509_EXTENSION *ex);
int __wrap_X509_CRL_verify(X509_CRL *crl, EVP_PKEY *pkey);
int __wrap_X509_CRL_sign(X509_CRL *crl, EVP_PKEY *pkey, const EVP_MD *md);
X509_CRL *__wrap_X509_CRL_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
int __wrap_X509_CRL_set_version(X509_CRL *crl, long version);
int __wrap_X509_CRL_set_issuer_name(X509_CRL *crl, const X509_NAME *name);
int __wrap_X509_CRL_set1_lastUpdate(X509_CRL *crl, const ASN1_TIME *tm);
int __wrap_X509_CRL_set1_nextUpdate(X509_CRL *crl, const ASN1_TIME *tm);
int __wrap_X509_CRL_add1_ext_i2d(
    X509_CRL *crl, int nid, void *value, int crit, unsigned long flags);
int __wrap_X509_CRL_get_ext_count(const X509_CRL *x);
int __wrap_X509_CRL_add_ext(X509_CRL *x, const X509_EXTENSION *ex, int loc);
STACK_OF(X509_REVOKED) *__wrap_X509_CRL_get_REVOKED(X509_CRL *crl);
int __wrap_X509_CRL_get0_by_serial(
    X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *serial);
X509_REVOKED *__wrap_X509_REVOKED_dup(const X509_REVOKED *rev);
int __wrap_X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
void __wrap_X509_CRL_free(X509_CRL *crl);
void __wrap_X509_REVOKED_free(X509_REVOKED *rev);

void __wrap_ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    function_called();
    check_expected(lib);
    check_expected(reason);

    va_start(args, fmt);
    ERR_vset_error(lib, reason, fmt, args);
    va_end(args);
}

int __wrap_X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)
{
    function_called();
    check_expected_ptr(a);
    check_expected_ptr(b);

    return mock_type(int);
}

int __wrap_ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y)
{
    function_called();
    check_expected_ptr(x);
    check_expected_ptr(y);

    return mock_type(int);
}

int __wrap_ASN1_OCTET_STRING_cmp(
    const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING *b)
{
    function_called();
    check_expected_ptr(a);
    check_expected_ptr(b);

    return mock_type(int);
}

int __wrap_X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos)
{
    function_called();
    check_expected_ptr(x);
    check_expected(nid);
    check_expected(lastpos);

    return mock_type(int);
}

X509_EXTENSION *__wrap_X509_CRL_get_ext(const X509_CRL *x, int loc)
{
    function_called();
    check_expected_ptr(x);
    check_expected(loc);

    return mock_ptr_type(X509_EXTENSION *);
}

ASN1_OCTET_STRING *__wrap_X509_EXTENSION_get_data(const X509_EXTENSION *ex)
{
    function_called();
    check_expected_ptr(ex);

    return mock_ptr_type(ASN1_OCTET_STRING *);
}

int __wrap_X509_CRL_verify(X509_CRL *crl, EVP_PKEY *pkey)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(pkey);

    return mock_type(int);
}

int __wrap_X509_CRL_sign(X509_CRL *crl, EVP_PKEY *pkey, const EVP_MD *md)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(pkey);
    check_expected_ptr(md);

    return mock_type(int);
}

X509_CRL *__wrap_X509_CRL_new_ex(OSSL_LIB_CTX *libctx, const char *propq)
{
    function_called();
    check_expected_ptr(libctx);
    check_expected_ptr(propq);

    return mock_ptr_type(X509_CRL *);
}

int __wrap_X509_CRL_set_version(X509_CRL *crl, long version)
{
    function_called();
    check_expected_ptr(crl);
    check_expected(version);

    return mock_type(int);
}

int __wrap_X509_CRL_set_issuer_name(X509_CRL *crl, const X509_NAME *name)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(name);

    return mock_type(int);
}

int __wrap_X509_CRL_set1_lastUpdate(X509_CRL *crl, const ASN1_TIME *tm)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(tm);

    return mock_type(int);
}

int __wrap_X509_CRL_set1_nextUpdate(X509_CRL *crl, const ASN1_TIME *tm)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(tm);

    return mock_type(int);
}

int __wrap_X509_CRL_add1_ext_i2d(
    X509_CRL *crl, int nid, void *value, int crit, unsigned long flags)
{
    function_called();
    check_expected_ptr(crl);
    check_expected(nid);
    check_expected_ptr(value);
    check_expected(crit);
    check_expected(flags);

    return mock_type(int);
}

int __wrap_X509_CRL_get_ext_count(const X509_CRL *x)
{
    function_called();
    check_expected_ptr(x);

    return mock_type(int);
}

int __wrap_X509_CRL_add_ext(X509_CRL *x, const X509_EXTENSION *ex, int loc)
{
    function_called();
    check_expected_ptr(x);
    check_expected_ptr(ex);
    check_expected(loc);

    return mock_type(int);
}

STACK_OF(X509_REVOKED) *__wrap_X509_CRL_get_REVOKED(X509_CRL *crl)
{
    function_called();
    check_expected_ptr(crl);

    return mock_ptr_type(STACK_OF(X509_REVOKED) *);
}

int __wrap_X509_CRL_get0_by_serial(
    X509_CRL *crl, X509_REVOKED **ret, const ASN1_INTEGER *serial)
{
    function_called();
    check_expected_ptr(crl);
    assert_non_null(ret);
    check_expected_ptr(serial);

    *ret = NULL;
    return mock_type(int);
}

X509_REVOKED *__wrap_X509_REVOKED_dup(const X509_REVOKED *rev)
{
    function_called();
    check_expected_ptr(rev);

    return mock_ptr_type(X509_REVOKED *);
}

int __wrap_X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)
{
    function_called();
    check_expected_ptr(crl);
    check_expected_ptr(rev);

    return mock_type(int);
}

void __wrap_X509_CRL_free(X509_CRL *crl)
{
    function_called();
    check_expected_ptr(crl);
}

void __wrap_X509_REVOKED_free(X509_REVOKED *rev)
{
    function_called();
    check_expected_ptr(rev);
}

/* expectations */

static void expect_ERR_set_error(int lib, int reason)
{
    expect_function_call(__wrap_ERR_set_error);
    expect_value(__wrap_ERR_set_error, lib, lib);
    expect_value(__wrap_ERR_set_error, reason, reason);
}

static void expect_X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b, int rc)
{
    expect_function_call(__wrap_X509_NAME_cmp);
    expect_value(__wrap_X509_NAME_cmp, a, a);
    expect_value(__wrap_X509_NAME_cmp, b, b);
    will_return(__wrap_X509_NAME_cmp, rc);
}

static void expect_ASN1_INTEGER_cmp(
    const ASN1_INTEGER *x, const ASN1_INTEGER *y, int rc)
{
    expect_function_call(__wrap_ASN1_INTEGER_cmp);
    expect_value(__wrap_ASN1_INTEGER_cmp, x, x);
    expect_value(__wrap_ASN1_INTEGER_cmp, y, y);
    will_return(__wrap_ASN1_INTEGER_cmp, rc);
}

static void expect_ASN1_OCTET_STRING_cmp(
    const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING *b, int rc)
{
    expect_function_call(__wrap_ASN1_OCTET_STRING_cmp);
    expect_value(__wrap_ASN1_OCTET_STRING_cmp, a, a);
    expect_value(__wrap_ASN1_OCTET_STRING_cmp, b, b);
    will_return(__wrap_ASN1_OCTET_STRING_cmp, rc);
}

static void expect_X509_CRL_get_ext_by_NID(
    const X509_CRL *x, int nid, int lastpos, int rc)
{
    expect_function_call(__wrap_X509_CRL_get_ext_by_NID);
    expect_value(__wrap_X509_CRL_get_ext_by_NID, x, x);
    expect_value(__wrap_X509_CRL_get_ext_by_NID, nid, nid);
    expect_value(__wrap_X509_CRL_get_ext_by_NID, lastpos, lastpos);
    will_return(__wrap_X509_CRL_get_ext_by_NID, rc);
}

static void expect_X509_CRL_get_ext(
    const X509_CRL *x, int loc, X509_EXTENSION *rc)
{
    expect_function_call(__wrap_X509_CRL_get_ext);
    expect_value(__wrap_X509_CRL_get_ext, x, x);
    expect_value(__wrap_X509_CRL_get_ext, loc, loc);
    will_return(__wrap_X509_CRL_get_ext, rc);
}

static void expect_X509_EXTENSION_get_data(
    const X509_EXTENSION *ex, ASN1_OCTET_STRING *rc)
{
    expect_function_call(__wrap_X509_EXTENSION_get_data);
    expect_value(__wrap_X509_EXTENSION_get_data, ex, ex);
    will_return(__wrap_X509_EXTENSION_get_data, rc);
}

static void expect_X509_CRL_verify(X509_CRL *crl, EVP_PKEY *pkey, int rc)
{
    expect_function_call(__wrap_X509_CRL_verify);
    expect_value(__wrap_X509_CRL_verify, crl, crl);
    expect_value(__wrap_X509_CRL_verify, pkey, pkey);
    will_return(__wrap_X509_CRL_verify, rc);
}

static void expect_X509_CRL_sign(
    X509_CRL *crl, EVP_PKEY *pkey, const EVP_MD *md, int rc)
{
    expect_function_call(__wrap_X509_CRL_sign);
    expect_value(__wrap_X509_CRL_sign, crl, crl);
    expect_value(__wrap_X509_CRL_sign, pkey, pkey);
    expect_value(__wrap_X509_CRL_sign, md, md);
    will_return(__wrap_X509_CRL_sign, rc);
}

static void expect_X509_CRL_new_ex(
    OSSL_LIB_CTX *libctx, const char *propq, X509_CRL *rc)
{
    expect_function_call(__wrap_X509_CRL_new_ex);
    expect_value(__wrap_X509_CRL_new_ex, libctx, libctx);
    expect_value(__wrap_X509_CRL_new_ex, propq, propq);
    will_return(__wrap_X509_CRL_new_ex, rc);
}

static void expect_X509_CRL_set_version(X509_CRL *crl, long version, int rc)
{
    expect_function_call(__wrap_X509_CRL_set_version);
    expect_value(__wrap_X509_CRL_set_version, crl, crl);
    expect_value(__wrap_X509_CRL_set_version, version, version);
    will_return(__wrap_X509_CRL_set_version, rc);
}

static void expect_X509_CRL_set_issuer_name(
    X509_CRL *crl, const X509_NAME *name, int rc)
{
    expect_function_call(__wrap_X509_CRL_set_issuer_name);
    expect_value(__wrap_X509_CRL_set_issuer_name, crl, crl);
    expect_value(__wrap_X509_CRL_set_issuer_name, name, name);
    will_return(__wrap_X509_CRL_set_issuer_name, rc);
}

static void expect_X509_CRL_set1_lastUpdate(
    X509_CRL *crl, const ASN1_TIME *tm, int rc)
{
    expect_function_call(__wrap_X509_CRL_set1_lastUpdate);
    expect_value(__wrap_X509_CRL_set1_lastUpdate, crl, crl);
    expect_value(__wrap_X509_CRL_set1_lastUpdate, tm, tm);
    will_return(__wrap_X509_CRL_set1_lastUpdate, rc);
}

static void expect_X509_CRL_set1_nextUpdate(
    X509_CRL *crl, const ASN1_TIME *tm, int rc)
{
    expect_function_call(__wrap_X509_CRL_set1_nextUpdate);
    expect_value(__wrap_X509_CRL_set1_nextUpdate, crl, crl);
    expect_value(__wrap_X509_CRL_set1_nextUpdate, tm, tm);
    will_return(__wrap_X509_CRL_set1_nextUpdate, rc);
}

static void expect_X509_CRL_add1_ext_i2d(
    X509_CRL *crl, int nid, void *value, int crit, unsigned long flags, int rc)
{
    expect_function_call(__wrap_X509_CRL_add1_ext_i2d);
    expect_value(__wrap_X509_CRL_add1_ext_i2d, crl, crl);
    expect_value(__wrap_X509_CRL_add1_ext_i2d, nid, nid);
    expect_value(__wrap_X509_CRL_add1_ext_i2d, value, value);
    expect_value(__wrap_X509_CRL_add1_ext_i2d, crit, crit);
    expect_value(__wrap_X509_CRL_add1_ext_i2d, flags, flags);
    will_return(__wrap_X509_CRL_add1_ext_i2d, rc);
}

static void expect_X509_CRL_get_ext_count(const X509_CRL *x, int rc)
{
    expect_function_call(__wrap_X509_CRL_get_ext_count);
    expect_value(__wrap_X509_CRL_get_ext_count, x, x);
    will_return(__wrap_X509_CRL_get_ext_count, rc);
}

static void expect_X509_CRL_add_ext(
    X509_CRL *x, const X509_EXTENSION *ex, int loc, int rc)
{
    expect_function_call(__wrap_X509_CRL_add_ext);
    expect_value(__wrap_X509_CRL_add_ext, x, x);
    expect_value(__wrap_X509_CRL_add_ext, ex, ex);
    expect_value(__wrap_X509_CRL_add_ext, loc, loc);
    will_return(__wrap_X509_CRL_add_ext, rc);
}

static void expect_X509_CRL_get_REVOKED(
    X509_CRL *crl, STACK_OF(X509_REVOKED) *rc)
{
    expect_function_call(__wrap_X509_CRL_get_REVOKED);
    expect_value(__wrap_X509_CRL_get_REVOKED, crl, crl);
    will_return(__wrap_X509_CRL_get_REVOKED, rc);
}

static void expect_X509_CRL_get0_by_serial(
    X509_CRL *crl, const ASN1_INTEGER *serial, int rc)
{
    expect_function_call(__wrap_X509_CRL_get0_by_serial);
    expect_value(__wrap_X509_CRL_get0_by_serial, crl, crl);
    expect_value(__wrap_X509_CRL_get0_by_serial, serial, serial);
    will_return(__wrap_X509_CRL_get0_by_serial, rc);
}

static void expect_X509_REVOKED_dup(const X509_REVOKED *rev, X509_REVOKED *rc)
{
    expect_function_call(__wrap_X509_REVOKED_dup);
    expect_value(__wrap_X509_REVOKED_dup, rev, rev);
    will_return(__wrap_X509_REVOKED_dup, rc);
}

static void expect_X509_CRL_add0_revoked(
    X509_CRL *crl, X509_REVOKED *rev, int rc)
{
    expect_function_call(__wrap_X509_CRL_add0_revoked);
    expect_value(__wrap_X509_CRL_add0_revoked, crl, crl);
    expect_value(__wrap_X509_CRL_add0_revoked, rev, rev);
    will_return(__wrap_X509_CRL_add0_revoked, rc);
}

static void expect_X509_CRL_free(X509_CRL *crl)
{
    expect_function_call(__wrap_X509_CRL_free);
    expect_value(__wrap_X509_CRL_free, crl, crl);
}

static void expect_X509_REVOKED_free(X509_REVOKED *rev)
{
    expect_function_call(__wrap_X509_REVOKED_free);
    expect_value(__wrap_X509_REVOKED_free, rev, rev);
}

/* helpers */

/* Init a valid CRL pair with names and issuers */
static void init_crl_pair(X509_CRL *base, X509_CRL *newer,
    X509_NAME *base_issuer, X509_NAME *newer_issuer, ASN1_INTEGER *base_num,
    ASN1_INTEGER *newer_num)
{
    memset(base, 0, sizeof(*base));
    memset(newer, 0, sizeof(*newer));
    base->crl_number = base_num;
    newer->crl_number = newer_num;
    base->crl.issuer = base_issuer;
    newer->crl.issuer = newer_issuer;
}

/* Init a valid CRL pair with names, issuers and update times. */
static void init_crl_pair_with_time(X509_CRL *base, X509_CRL *newer,
    X509_NAME *base_issuer, X509_NAME *newer_issuer, ASN1_INTEGER *base_num,
    ASN1_INTEGER *newer_num, ASN1_TIME *newer_last, ASN1_TIME *newer_next)
{
    init_crl_pair(base, newer, base_issuer, newer_issuer, base_num, newer_num);
    newer->crl.lastUpdate = newer_last;
    newer->crl.nextUpdate = newer_next;
}

/* X509_CRL_diff */

/* base->base_crl_number not NULL */
static void test_crl_diff_base_already_delta(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num, base_delta;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    base.base_crl_number = &base_delta;

    expect_ERR_set_error(ERR_LIB_X509, X509_R_CRL_ALREADY_DELTA);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* newer->base_crl_number not NULL */
static void test_crl_diff_newer_already_delta(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num, newer_delta;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    newer.base_crl_number = &newer_delta;

    expect_ERR_set_error(ERR_LIB_X509, X509_R_CRL_ALREADY_DELTA);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* base->crl_number NULL */
static void test_crl_diff_base_no_crl_number(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    base.crl_number = NULL;

    expect_ERR_set_error(ERR_LIB_X509, X509_R_NO_CRL_NUMBER);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* newer->crl_number NULL */
static void test_crl_diff_newer_no_crl_number(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    newer.crl_number = NULL;

    expect_ERR_set_error(ERR_LIB_X509, X509_R_NO_CRL_NUMBER);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_NAME_cmp returns non-zero */
static void test_crl_diff_issuer_mismatch(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 1);
    expect_ERR_set_error(ERR_LIB_X509, X509_R_ISSUER_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match AKID: exta set, extb NULL */
static void test_crl_diff_akid_only_on_base(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    X509_EXTENSION ext_a;
    ASN1_OCTET_STRING os_a;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    /* crl_extension_match(base, newer, AKID): found on base, not on newer */
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&base, 0, &ext_a);
    expect_X509_EXTENSION_get_data(&ext_a, &os_a);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_AKID_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match AKID: exta NULL, extb set */
static void test_crl_diff_akid_only_on_newer(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    X509_EXTENSION ext_b;
    ASN1_OCTET_STRING os_b;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&newer, 0, &ext_b);
    expect_X509_EXTENSION_get_data(&ext_b, &os_b);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_AKID_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match AKID: multiple occurrences on base */
static void test_crl_diff_akid_dup_on_base(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, 0, 1);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_AKID_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match AKID: multiple occurrences on newer */
static void test_crl_diff_akid_dup_on_newer(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, 0, 1);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_AKID_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match AKID: ASN1_OCTET_STRING_cmp non-zero */
static void test_crl_diff_akid_data_mismatch(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    X509_EXTENSION ext_a, ext_b;
    ASN1_OCTET_STRING os_a, os_b;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    /* base: found at 0, no dup */
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&base, 0, &ext_a);
    expect_X509_EXTENSION_get_data(&ext_a, &os_a);
    /* newer: found at 0, no dup */
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&newer, 0, &ext_b);
    expect_X509_EXTENSION_get_data(&ext_b, &os_b);
    /* compare returns non-zero */
    expect_ASN1_OCTET_STRING_cmp(&os_a, &os_b, -1);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_AKID_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* crl_extension_match IDP: multiple occurrences on base */
static void test_crl_diff_idp_dup_on_base(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    /* AKID: both absent */
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    /* IDP: duplicate on base */
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, 1);
    expect_X509_CRL_get_ext_by_NID(&base, NID_issuing_distribution_point, 1, 2);

    expect_ERR_set_error(ERR_LIB_X509, X509_R_IDP_MISMATCH);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* ASN1_INTEGER_cmp(newer, base) <= 0 */
static void test_crl_diff_crl_number_not_newer(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    /* AKID + IDP: both absent */
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 0);
    expect_ERR_set_error(ERR_LIB_X509, X509_R_NEWER_CRL_NOT_NEWER);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_CRL_verify(base) fails */
static void test_crl_diff_base_verify_fail(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    EVP_PKEY skey;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_verify(&base, &skey, 0);
    expect_ERR_set_error(ERR_LIB_X509, X509_R_CRL_VERIFY_FAILURE);

    assert_null(X509_CRL_diff(&base, &newer, &skey, NULL, 0));
}

/* X509_CRL_verify(newer) fails, base passes */
static void test_crl_diff_newer_verify_fail(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    EVP_PKEY skey;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_verify(&base, &skey, 1);
    expect_X509_CRL_verify(&newer, &skey, 0);
    expect_ERR_set_error(ERR_LIB_X509, X509_R_CRL_VERIFY_FAILURE);

    assert_null(X509_CRL_diff(&base, &newer, &skey, NULL, 0));
}

/* X509_CRL_new_ex returns NULL */
static void test_crl_diff_new_ex_fail(void **state)
{
    X509_CRL base, newer;
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, NULL);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(NULL);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_CRL_set_version fails */
static void test_crl_diff_set_version_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    memset(&mock_delta, 0, sizeof(mock_delta));

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 0);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_CRL_set_issuer_name fails */
static void test_crl_diff_set_issuer_name_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;

    (void)state;
    init_crl_pair(
        &base, &newer, &base_issuer, &newer_issuer, &base_num, &newer_num);
    memset(&mock_delta, 0, sizeof(mock_delta));

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 0);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_CRL_add1_ext_i2d fails */
static void test_crl_diff_add1_ext_i2d_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 0);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_CRL_add_ext fails in extension copy loop */
static void test_crl_diff_add_ext_copy_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_EXTENSION ext0;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    /* ext copy loop: 1 extension, add_ext fails */
    expect_X509_CRL_get_ext_count(&newer, 1);
    expect_X509_CRL_get_ext(&newer, 0, &ext0);
    expect_X509_CRL_add_ext(&mock_delta, &ext0, -1, 0);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));
}

/* X509_REVOKED_dup returns NULL */
static void test_crl_diff_revoked_dup_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_REVOKED rev_entry;
    STACK_OF(X509_REVOKED) *revs;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    revs = sk_X509_REVOKED_new_null();
    assert_non_null(revs);
    sk_X509_REVOKED_push(revs, &rev_entry);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, revs);
    expect_X509_CRL_get0_by_serial(&base, &rev_entry.serialNumber, 0);
    expect_X509_REVOKED_dup(&rev_entry, NULL);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_ASN1_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));

    sk_X509_REVOKED_free(revs);
}

/* X509_CRL_add0_revoked fails */
static void test_crl_diff_add0_revoked_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_REVOKED rev_entry, dup_rev;
    STACK_OF(X509_REVOKED) *revs;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    revs = sk_X509_REVOKED_new_null();
    assert_non_null(revs);
    sk_X509_REVOKED_push(revs, &rev_entry);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, revs);
    expect_X509_CRL_get0_by_serial(&base, &rev_entry.serialNumber, 0);
    expect_X509_REVOKED_dup(&rev_entry, &dup_rev);
    expect_X509_CRL_add0_revoked(&mock_delta, &dup_rev, 0);
    expect_X509_REVOKED_free(&dup_rev);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, NULL, NULL, 0));

    sk_X509_REVOKED_free(revs);
}

/* X509_CRL_sign fails */
static void test_crl_diff_sign_fail(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    EVP_PKEY skey;
    EVP_MD md;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_verify(&base, &skey, 1);
    expect_X509_CRL_verify(&newer, &skey, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, NULL);

    expect_X509_CRL_sign(&mock_delta, &skey, &md, 0);
    expect_ERR_set_error(ERR_LIB_X509, ERR_R_X509_LIB);
    expect_X509_CRL_free(&mock_delta);

    assert_null(X509_CRL_diff(&base, &newer, &skey, &md, 0));
}

/* no ext, no revoked, skey NULL */
static void test_crl_diff_success_basic(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, NULL);

    assert_ptr_equal(X509_CRL_diff(&base, &newer, NULL, NULL, 0), &mock_delta);
}

/* AKID data matches on both CRLs */
static void test_crl_diff_success_akid_match(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_EXTENSION ext_a, ext_b;
    ASN1_OCTET_STRING os_a, os_b;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    /* AKID: both present, data matches */
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&base, 0, &ext_a);
    expect_X509_EXTENSION_get_data(&ext_a, &os_a);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, -1, 0);
    expect_X509_CRL_get_ext_by_NID(&newer, NID_authority_key_identifier, 0, -1);
    expect_X509_CRL_get_ext(&newer, 0, &ext_b);
    expect_X509_EXTENSION_get_data(&ext_b, &os_b);
    expect_ASN1_OCTET_STRING_cmp(&os_a, &os_b, 0);

    /* IDP: both absent */
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, NULL);

    assert_ptr_equal(X509_CRL_diff(&base, &newer, NULL, NULL, 0), &mock_delta);
}

/* extension copy loop with 1 extension */
static void test_crl_diff_success_ext_copy(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_EXTENSION ext0;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    /* ext copy: 1 extension copied successfully */
    expect_X509_CRL_get_ext_count(&newer, 1);
    expect_X509_CRL_get_ext(&newer, 0, &ext0);
    expect_X509_CRL_add_ext(&mock_delta, &ext0, -1, 1);
    expect_X509_CRL_get_ext_count(&newer, 1);

    expect_X509_CRL_get_REVOKED(&newer, NULL);

    assert_ptr_equal(X509_CRL_diff(&base, &newer, NULL, NULL, 0), &mock_delta);
}

/* revoked entry not in base, added to delta */
static void test_crl_diff_success_revoked_new(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_REVOKED rev_entry, dup_rev;
    STACK_OF(X509_REVOKED) *revs;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    revs = sk_X509_REVOKED_new_null();
    assert_non_null(revs);
    sk_X509_REVOKED_push(revs, &rev_entry);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, revs);
    expect_X509_CRL_get0_by_serial(&base, &rev_entry.serialNumber, 0);
    expect_X509_REVOKED_dup(&rev_entry, &dup_rev);
    expect_X509_CRL_add0_revoked(&mock_delta, &dup_rev, 1);

    assert_ptr_equal(X509_CRL_diff(&base, &newer, NULL, NULL, 0), &mock_delta);

    sk_X509_REVOKED_free(revs);
}

/* revoked entry already in base, skipped */
static void test_crl_diff_success_revoked_in_base(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    X509_REVOKED rev_entry;
    STACK_OF(X509_REVOKED) *revs;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    revs = sk_X509_REVOKED_new_null();
    assert_non_null(revs);
    sk_X509_REVOKED_push(revs, &rev_entry);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, revs);
    expect_X509_CRL_get0_by_serial(&base, &rev_entry.serialNumber, 1);
    /* no dup/add: entry skipped */

    assert_ptr_equal(X509_CRL_diff(&base, &newer, NULL, NULL, 0), &mock_delta);

    sk_X509_REVOKED_free(revs);
}

/* skey + md: verify and sign both pass */
static void test_crl_diff_success_with_sign(void **state)
{
    X509_CRL base, newer, mock_delta = { 0 };
    X509_NAME base_issuer, newer_issuer;
    ASN1_INTEGER base_num, newer_num;
    ASN1_TIME newer_last, newer_next;
    EVP_PKEY skey;
    EVP_MD md;

    (void)state;
    init_crl_pair_with_time(&base, &newer, &base_issuer, &newer_issuer,
        &base_num, &newer_num, &newer_last, &newer_next);

    expect_X509_NAME_cmp(&base_issuer, &newer_issuer, 0);

    expect_X509_CRL_get_ext_by_NID(&base, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_authority_key_identifier, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &base, NID_issuing_distribution_point, -1, -1);
    expect_X509_CRL_get_ext_by_NID(
        &newer, NID_issuing_distribution_point, -1, -1);

    expect_ASN1_INTEGER_cmp(&newer_num, &base_num, 1);

    expect_X509_CRL_verify(&base, &skey, 1);
    expect_X509_CRL_verify(&newer, &skey, 1);

    expect_X509_CRL_new_ex(NULL, NULL, &mock_delta);
    expect_X509_CRL_set_version(&mock_delta, X509_CRL_VERSION_2, 1);
    expect_X509_CRL_set_issuer_name(&mock_delta, &newer_issuer, 1);
    expect_X509_CRL_set1_lastUpdate(&mock_delta, &newer_last, 1);
    expect_X509_CRL_set1_nextUpdate(&mock_delta, &newer_next, 1);
    expect_X509_CRL_add1_ext_i2d(
        &mock_delta, NID_delta_crl, &base_num, 1, 0, 1);

    expect_X509_CRL_get_ext_count(&newer, 0);
    expect_X509_CRL_get_REVOKED(&newer, NULL);

    expect_X509_CRL_sign(&mock_delta, &skey, &md, 1);

    assert_ptr_equal(X509_CRL_diff(&base, &newer, &skey, &md, 0), &mock_delta);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* X509_CRL_diff */
        cmocka_unit_test(test_crl_diff_base_already_delta),
        cmocka_unit_test(test_crl_diff_newer_already_delta),
        cmocka_unit_test(test_crl_diff_base_no_crl_number),
        cmocka_unit_test(test_crl_diff_newer_no_crl_number),
        cmocka_unit_test(test_crl_diff_issuer_mismatch),
        cmocka_unit_test(test_crl_diff_akid_only_on_base),
        cmocka_unit_test(test_crl_diff_akid_only_on_newer),
        cmocka_unit_test(test_crl_diff_akid_dup_on_base),
        cmocka_unit_test(test_crl_diff_akid_dup_on_newer),
        cmocka_unit_test(test_crl_diff_akid_data_mismatch),
        cmocka_unit_test(test_crl_diff_idp_dup_on_base),
        cmocka_unit_test(test_crl_diff_crl_number_not_newer),
        cmocka_unit_test(test_crl_diff_base_verify_fail),
        cmocka_unit_test(test_crl_diff_newer_verify_fail),
        cmocka_unit_test(test_crl_diff_new_ex_fail),
        cmocka_unit_test(test_crl_diff_set_version_fail),
        cmocka_unit_test(test_crl_diff_set_issuer_name_fail),
        cmocka_unit_test(test_crl_diff_add1_ext_i2d_fail),
        cmocka_unit_test(test_crl_diff_add_ext_copy_fail),
        cmocka_unit_test(test_crl_diff_revoked_dup_fail),
        cmocka_unit_test(test_crl_diff_add0_revoked_fail),
        cmocka_unit_test(test_crl_diff_sign_fail),
        cmocka_unit_test(test_crl_diff_success_basic),
        cmocka_unit_test(test_crl_diff_success_akid_match),
        cmocka_unit_test(test_crl_diff_success_ext_copy),
        cmocka_unit_test(test_crl_diff_success_revoked_new),
        cmocka_unit_test(test_crl_diff_success_revoked_in_base),
        cmocka_unit_test(test_crl_diff_success_with_sign),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
