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
#include <string.h>
#include <cmocka.h>

#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include "../ssl_local.h"
#include "statem_local.h"

/* wraps */

void __wrap_ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason,
    const char *fmt, ...);
void __wrap_OPENSSL_die(const char *message, const char *file, int line);
int __wrap_ssl3_renegotiate_check(SSL *ssl, int initok);
int __wrap_tls_setup_handshake(SSL_CONNECTION *s);
int __wrap_tls13_restore_handshake_digest_for_pha(SSL_CONNECTION *s);

void __wrap_ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason,
    const char *fmt, ...)
{
    function_called();
    check_expected_ptr(s);
    check_expected(al);
    check_expected(reason);
    (void)fmt;
    s->statem.in_init = 1;
    s->statem.state = MSG_FLOW_ERROR;
}

void __wrap_OPENSSL_die(const char *message, const char *file, int line)
{
    function_called();
}

int __wrap_ssl3_renegotiate_check(SSL *ssl, int initok)
{
    function_called();
    check_expected_ptr(ssl);
    check_expected(initok);
    return mock_type(int);
}

int __wrap_tls_setup_handshake(SSL_CONNECTION *s)
{
    function_called();
    check_expected_ptr(s);
    return mock_type(int);
}

int __wrap_tls13_restore_handshake_digest_for_pha(SSL_CONNECTION *s)
{
    function_called();
    check_expected_ptr(s);
    return mock_type(int);
}

/* vtable stubs */

static int stub_setup_key_block(SSL_CONNECTION *s)
{
    function_called();
    check_expected_ptr(s);
    return mock_type(int);
}

static int stub_change_cipher_state(SSL_CONNECTION *s, int which)
{
    function_called();
    check_expected_ptr(s);
    check_expected(which);
    return mock_type(int);
}

/* expectations */

static void expect_ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason)
{
    expect_function_call(__wrap_ossl_statem_fatal);
    expect_value(__wrap_ossl_statem_fatal, s, s);
    expect_value(__wrap_ossl_statem_fatal, al, al);
    expect_value(__wrap_ossl_statem_fatal, reason, reason);
}

static void expect_OPENSSL_die(void)
{
    expect_function_call(__wrap_OPENSSL_die);
}

static void expect_ssl3_renegotiate_check(SSL *ssl, int initok, int rc)
{
    expect_function_call(__wrap_ssl3_renegotiate_check);
    expect_value(__wrap_ssl3_renegotiate_check, ssl, ssl);
    expect_value(__wrap_ssl3_renegotiate_check, initok, initok);
    will_return(__wrap_ssl3_renegotiate_check, rc);
}

static void expect_tls_setup_handshake(SSL_CONNECTION *s, int rc)
{
    expect_function_call(__wrap_tls_setup_handshake);
    expect_value(__wrap_tls_setup_handshake, s, s);
    will_return(__wrap_tls_setup_handshake, rc);
}

static void expect_tls13_restore_handshake_digest_for_pha(
    SSL_CONNECTION *s, int rc)
{
    expect_function_call(__wrap_tls13_restore_handshake_digest_for_pha);
    expect_value(__wrap_tls13_restore_handshake_digest_for_pha, s, s);
    will_return(__wrap_tls13_restore_handshake_digest_for_pha, rc);
}

/* fake methods */

static SSL3_ENC_METHOD fake_enc = {
    .enc_flags = 0,
    .setup_key_block = stub_setup_key_block,
    .change_cipher_state = stub_change_cipher_state,
};

static SSL3_ENC_METHOD fake_enc_dtls = {
    .enc_flags = SSL_ENC_FLAG_DTLS,
    .setup_key_block = stub_setup_key_block,
    .change_cipher_state = stub_change_cipher_state,
};

static SSL_METHOD fake_method_tls12 = {
    .version = TLS1_2_VERSION,
    .ssl3_enc = &fake_enc,
};

static SSL_METHOD fake_method_tls13 = {
    .version = TLS1_3_VERSION,
    .ssl3_enc = &fake_enc,
};

static SSL_METHOD fake_method_dtls = {
    .version = DTLS1_2_VERSION,
    .ssl3_enc = &fake_enc_dtls,
};

/* helpers */

static void init_client_common(SSL_CONNECTION *s, SSL_CTX *ctx,
    SSL_CIPHER *cipher, SSL_SESSION *session, const SSL_METHOD *method,
    int version)
{
    memset(s, 0, sizeof(*s));
    memset(ctx, 0, sizeof(*ctx));
    memset(cipher, 0, sizeof(*cipher));
    memset(session, 0, sizeof(*session));

    s->ssl.method = (SSL_METHOD *)method;
    s->ssl.ctx = ctx;
    s->version = version;
    s->server = 0;
    s->session = session;
    s->s3.tmp.new_cipher = cipher;

    cipher->algorithm_auth = SSL_aRSA;
    cipher->algorithm_mkey = SSL_kRSA;
}

static void init_dtls_client(SSL_CONNECTION *s, SSL_CTX *ctx,
    SSL_CIPHER *cipher, SSL_SESSION *session, DTLS1_STATE *d1)
{
    init_client_common(s, ctx, cipher, session, &fake_method_dtls,
        DTLS1_2_VERSION);
    memset(d1, 0, sizeof(*d1));
    s->d1 = d1;
}

#define INIT_TLS12(s, ctx, cipher)                  \
    SSL_CONNECTION s;                               \
    SSL_CTX ctx;                                    \
    SSL_CIPHER cipher;                              \
    SSL_SESSION session;                            \
    (void)state;                                    \
    init_client_common(&s, &ctx, &cipher, &session, \
        &fake_method_tls12, TLS1_2_VERSION)

#define INIT_TLS13(s, ctx, cipher)                  \
    SSL_CONNECTION s;                               \
    SSL_CTX ctx;                                    \
    SSL_CIPHER cipher;                              \
    SSL_SESSION session;                            \
    (void)state;                                    \
    init_client_common(&s, &ctx, &cipher, &session, \
        &fake_method_tls13, TLS1_3_VERSION)

#define INIT_DTLS(s, ctx, cipher) \
    SSL_CONNECTION s;             \
    SSL_CTX ctx;                  \
    SSL_CIPHER cipher;            \
    SSL_SESSION session;          \
    DTLS1_STATE d1;               \
    (void)state;                  \
    init_dtls_client(&s, &ctx, &cipher, &session, &d1)

#define READ_TRAN(from, mt, expected_rc, expected_to)                     \
    do {                                                                  \
        s.statem.hand_state = (from);                                     \
        assert_int_equal(                                                 \
            ossl_statem_client_read_transition(&s, (mt)), (expected_rc)); \
        assert_int_equal(s.statem.hand_state, (expected_to));             \
    } while (0)

#define WRITE_TRAN(from, expected_rc, expected_to)                   \
    do {                                                             \
        s.statem.hand_state = (from);                                \
        assert_int_equal(                                            \
            ossl_statem_client_write_transition(&s), (expected_rc)); \
        assert_int_equal(s.statem.hand_state, (expected_to));        \
    } while (0)

static void test_read_cw_clnt_hello_to_srvr_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, SSL3_MT_SERVER_HELLO,
        1, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cw_clnt_hello_dtls_to_hello_verify(void **state)
{
    INIT_DTLS(s, ctx, cipher);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, DTLS1_MT_HELLO_VERIFY_REQUEST,
        1, DTLS_ST_CR_HELLO_VERIFY_REQUEST);
}

static void test_read_cw_clnt_hello_hello_verify_rejected_in_tls(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, DTLS1_MT_HELLO_VERIFY_REQUEST,
        0, TLS_ST_CW_CLNT_HELLO);
}

static void test_read_cw_clnt_hello_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, SSL3_MT_FINISHED,
        0, TLS_ST_CW_CLNT_HELLO);
}

static void test_read_early_data_to_srvr_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_EARLY_DATA, SSL3_MT_SERVER_HELLO,
        1, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_early_data_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_EARLY_DATA, SSL3_MT_CERTIFICATE,
        0, TLS_ST_EARLY_DATA);
}

static void test_read_cr_srvr_hello_full_to_cert(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_CERTIFICATE,
        1, TLS_ST_CR_CERT);
}

static void test_read_cr_srvr_hello_resume_ticket_expected(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    s.ext.ticket_expected = 1;
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_NEWSESSION_TICKET,
        1, TLS_ST_CR_SESSION_TICKET);
}

static void test_read_cr_srvr_hello_resume_no_ticket_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_CHANGE_CIPHER_SPEC,
        1, TLS_ST_CR_CHANGE);
}

static void test_read_cr_srvr_hello_resume_unexpected_ccs_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    s.ext.ticket_expected = 1;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_CHANGE_CIPHER_SPEC,
        0, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cr_srvr_hello_resume_unexpected_nst_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_NEWSESSION_TICKET,
        0, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cr_srvr_hello_dtls_to_hello_verify(void **state)
{
    INIT_DTLS(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, DTLS1_MT_HELLO_VERIFY_REQUEST,
        1, DTLS_ST_CR_HELLO_VERIFY_REQUEST);
}

static void test_read_cr_srvr_hello_anon_ske_expected(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_auth = SSL_aPSK;
    cipher.algorithm_mkey = SSL_kDHEPSK;
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_SERVER_KEY_EXCHANGE,
        1, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_srvr_hello_anon_psk_optional_ske(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_auth = SSL_aPSK;
    cipher.algorithm_mkey = SSL_kPSK;
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_SERVER_KEY_EXCHANGE,
        1, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_srvr_hello_anon_no_ske_to_done(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_auth = SSL_aNULL;
    cipher.algorithm_mkey = SSL_kRSA;
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_SERVER_DONE,
        1, TLS_ST_CR_SRVR_DONE);
}

static void test_read_cr_srvr_hello_anon_cert_req_rejected(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_auth = SSL_aPSK;
    cipher.algorithm_mkey = SSL_kDHEPSK;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_CERTIFICATE_REQUEST,
        0, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cr_srvr_hello_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_FINISHED,
        0, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cr_cert_to_cert_status(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.ext.status_expected = 1;
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_CERTIFICATE_STATUS,
        1, TLS_ST_CR_CERT_STATUS);
}

static void test_read_cr_cert_status_not_expected_falls_through_to_ske(
    void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_mkey = SSL_kDHE;
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_SERVER_KEY_EXCHANGE,
        1, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_cert_no_ske_to_cert_req(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_CERTIFICATE_REQUEST,
        1, TLS_ST_CR_CERT_REQ);
}

static void test_read_cr_cert_no_ske_to_done(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_SERVER_DONE,
        1, TLS_ST_CR_SRVR_DONE);
}

static void test_read_cr_cert_ske_expected_but_other_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_mkey = SSL_kDHE;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_CERTIFICATE_REQUEST,
        0, TLS_ST_CR_CERT);
}

static void test_read_cr_cert_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_FINISHED,
        0, TLS_ST_CR_CERT);
}

static void test_read_cr_cert_status_to_ske(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_mkey = SSL_kDHE;
    READ_TRAN(TLS_ST_CR_CERT_STATUS, SSL3_MT_SERVER_KEY_EXCHANGE,
        1, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_cert_status_to_cert_req(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT_STATUS, SSL3_MT_CERTIFICATE_REQUEST,
        1, TLS_ST_CR_CERT_REQ);
}

static void test_read_cr_cert_status_to_done(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT_STATUS, SSL3_MT_SERVER_DONE,
        1, TLS_ST_CR_SRVR_DONE);
}

static void test_read_cr_cert_status_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT_STATUS, SSL3_MT_FINISHED,
        0, TLS_ST_CR_CERT_STATUS);
}

static void test_read_cr_key_exch_to_cert_req(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_KEY_EXCH, SSL3_MT_CERTIFICATE_REQUEST,
        1, TLS_ST_CR_CERT_REQ);
}

static void test_read_cr_key_exch_to_done(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_KEY_EXCH, SSL3_MT_SERVER_DONE,
        1, TLS_ST_CR_SRVR_DONE);
}

static void test_read_cr_key_exch_anon_cert_req_rejected(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    cipher.algorithm_auth = SSL_aPSK;
    cipher.algorithm_mkey = SSL_kDHEPSK;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_KEY_EXCH, SSL3_MT_CERTIFICATE_REQUEST,
        0, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_key_exch_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_KEY_EXCH, SSL3_MT_FINISHED,
        0, TLS_ST_CR_KEY_EXCH);
}

static void test_read_cr_cert_req_to_done(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT_REQ, SSL3_MT_SERVER_DONE,
        1, TLS_ST_CR_SRVR_DONE);
}

static void test_read_cr_cert_req_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT_REQ, SSL3_MT_FINISHED,
        0, TLS_ST_CR_CERT_REQ);
}

static void test_read_cw_finished_ticket_expected_to_nst(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.ext.ticket_expected = 1;
    READ_TRAN(TLS_ST_CW_FINISHED, SSL3_MT_NEWSESSION_TICKET,
        1, TLS_ST_CR_SESSION_TICKET);
}

static void test_read_cw_finished_no_ticket_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CW_FINISHED, SSL3_MT_CHANGE_CIPHER_SPEC,
        1, TLS_ST_CR_CHANGE);
}

static void test_read_cw_finished_ticket_expected_unexpected_ccs_fatal(
    void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.ext.ticket_expected = 1;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CW_FINISHED, SSL3_MT_CHANGE_CIPHER_SPEC,
        0, TLS_ST_CW_FINISHED);
}

static void test_read_cw_finished_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CW_FINISHED, SSL3_MT_FINISHED,
        0, TLS_ST_CW_FINISHED);
}

static void test_read_cr_session_ticket_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_SESSION_TICKET, SSL3_MT_CHANGE_CIPHER_SPEC,
        1, TLS_ST_CR_CHANGE);
}

static void test_read_cr_session_ticket_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SESSION_TICKET, SSL3_MT_FINISHED,
        0, TLS_ST_CR_SESSION_TICKET);
}

static void test_read_cr_change_to_finished(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CHANGE, SSL3_MT_FINISHED,
        1, TLS_ST_CR_FINISHED);
}

static void test_read_cr_change_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CHANGE, SSL3_MT_CERTIFICATE,
        0, TLS_ST_CR_CHANGE);
}

static void test_read_ok_to_hello_req(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    READ_TRAN(TLS_ST_OK, SSL3_MT_HELLO_REQUEST,
        1, TLS_ST_CR_HELLO_REQ);
}

static void test_read_ok_bogus_mt_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_OK, SSL3_MT_FINISHED,
        0, TLS_ST_OK);
}

static void test_read_cw_clnt_hello_tls13_to_srvr_hello(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, SSL3_MT_SERVER_HELLO,
        1, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cw_clnt_hello_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CW_CLNT_HELLO, SSL3_MT_CERTIFICATE,
        0, TLS_ST_CW_CLNT_HELLO);
}

static void test_read_cr_srvr_hello_tls13_to_encrypted_extensions(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_ENCRYPTED_EXTENSIONS,
        1, TLS_ST_CR_ENCRYPTED_EXTENSIONS);
}

static void test_read_cr_srvr_hello_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_SRVR_HELLO, SSL3_MT_CERTIFICATE,
        0, TLS_ST_CR_SRVR_HELLO);
}

static void test_read_cr_ee_resume_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.hit = 1;
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_FINISHED,
        1, TLS_ST_CR_FINISHED);
}

static void test_read_cr_ee_full_to_cert_req(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_CERTIFICATE_REQUEST,
        1, TLS_ST_CR_CERT_REQ);
}

static void test_read_cr_ee_full_to_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_CERTIFICATE,
        1, TLS_ST_CR_CERT);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_read_cr_ee_full_to_comp_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.ext.compress_certificate_sent = 1;
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_COMPRESSED_CERTIFICATE,
        1, TLS_ST_CR_COMP_CERT);
}

static void test_read_cr_ee_full_comp_cert_not_sent_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_COMPRESSED_CERTIFICATE,
        0, TLS_ST_CR_ENCRYPTED_EXTENSIONS);
}
#endif

static void test_read_cr_ee_resume_unexpected_cert_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.hit = 1;
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_CERTIFICATE,
        0, TLS_ST_CR_ENCRYPTED_EXTENSIONS);
}

static void test_read_cr_ee_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_ENCRYPTED_EXTENSIONS, SSL3_MT_HELLO_REQUEST,
        0, TLS_ST_CR_ENCRYPTED_EXTENSIONS);
}

static void test_read_cr_cert_req_tls13_to_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT_REQ, SSL3_MT_CERTIFICATE,
        1, TLS_ST_CR_CERT);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_read_cr_cert_req_tls13_to_comp_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.ext.compress_certificate_sent = 1;
    READ_TRAN(TLS_ST_CR_CERT_REQ, SSL3_MT_COMPRESSED_CERTIFICATE,
        1, TLS_ST_CR_COMP_CERT);
}
#endif

static void test_read_cr_cert_req_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT_REQ, SSL3_MT_FINISHED,
        0, TLS_ST_CR_CERT_REQ);
}

static void test_read_cr_cert_tls13_to_cert_vrfy(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_CERTIFICATE_VERIFY,
        1, TLS_ST_CR_CERT_VRFY);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_read_cr_comp_cert_tls13_to_cert_vrfy(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_COMP_CERT, SSL3_MT_CERTIFICATE_VERIFY,
        1, TLS_ST_CR_CERT_VRFY);
}
#endif

static void test_read_cr_cert_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT, SSL3_MT_FINISHED,
        0, TLS_ST_CR_CERT);
}

static void test_read_cr_cert_vrfy_tls13_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_CR_CERT_VRFY, SSL3_MT_FINISHED,
        1, TLS_ST_CR_FINISHED);
}

static void test_read_cr_cert_vrfy_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_CR_CERT_VRFY, SSL3_MT_CERTIFICATE,
        0, TLS_ST_CR_CERT_VRFY);
}

static void test_read_ok_tls13_to_session_ticket(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_OK, SSL3_MT_NEWSESSION_TICKET,
        1, TLS_ST_CR_SESSION_TICKET);
}

static void test_read_ok_tls13_to_key_update(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    READ_TRAN(TLS_ST_OK, SSL3_MT_KEY_UPDATE,
        1, TLS_ST_CR_KEY_UPDATE);
}

static void test_read_ok_tls13_pha_cert_req(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.post_handshake_auth = SSL_PHA_EXT_SENT;
    expect_tls13_restore_handshake_digest_for_pha(&s, 1);
    READ_TRAN(TLS_ST_OK, SSL3_MT_CERTIFICATE_REQUEST,
        1, TLS_ST_CR_CERT_REQ);
    assert_int_equal(s.post_handshake_auth, SSL_PHA_REQUESTED);
}

static void test_read_ok_tls13_pha_digest_restore_fail(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.post_handshake_auth = SSL_PHA_EXT_SENT;
    expect_tls13_restore_handshake_digest_for_pha(&s, 0);
    expect_ossl_statem_fatal(&s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_OK, SSL3_MT_CERTIFICATE_REQUEST,
        0, TLS_ST_OK);
}

static void test_read_ok_tls13_cert_req_no_pha_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_OK, SSL3_MT_CERTIFICATE_REQUEST,
        0, TLS_ST_OK);
}

static void test_read_ok_tls13_bogus_mt_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL3_AD_UNEXPECTED_MESSAGE,
        SSL_R_UNEXPECTED_MESSAGE);
    READ_TRAN(TLS_ST_OK, SSL3_MT_FINISHED,
        0, TLS_ST_OK);
}

static void test_write_ok_no_renegotiate_finishes(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_OK, WRITE_TRAN_FINISHED, TLS_ST_OK);
}

static void test_write_ok_renegotiate_to_clnt_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.renegotiate = 1;
    WRITE_TRAN(TLS_ST_OK, WRITE_TRAN_CONTINUE, TLS_ST_CW_CLNT_HELLO);
}

static void test_write_before_to_clnt_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_BEFORE, WRITE_TRAN_CONTINUE, TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cw_clnt_hello_no_early_data_finishes(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_CLNT_HELLO, WRITE_TRAN_FINISHED,
        TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cw_clnt_hello_early_data_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.early_data_state = SSL_EARLY_DATA_CONNECTING;
    s.options = SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    WRITE_TRAN(TLS_ST_CW_CLNT_HELLO, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cw_clnt_hello_early_data_no_compat_to_early_data(
    void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.early_data_state = SSL_EARLY_DATA_CONNECTING;
    WRITE_TRAN(TLS_ST_CW_CLNT_HELLO, WRITE_TRAN_CONTINUE, TLS_ST_EARLY_DATA);
}

static void test_write_cr_srvr_hello_compat_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.options = SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    WRITE_TRAN(TLS_ST_CR_SRVR_HELLO, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cr_srvr_hello_compat_after_early_data_to_clnt_hello(
    void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.options = SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    s.early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;
    WRITE_TRAN(TLS_ST_CR_SRVR_HELLO, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cr_srvr_hello_no_compat_to_clnt_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_SRVR_HELLO, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_CLNT_HELLO);
}

static void test_write_early_data_finishes(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_EARLY_DATA, WRITE_TRAN_FINISHED, TLS_ST_EARLY_DATA);
}

static void test_write_dtls_hello_verify_to_clnt_hello(void **state)
{
    INIT_DTLS(s, ctx, cipher);
    WRITE_TRAN(DTLS_ST_CR_HELLO_VERIFY_REQUEST, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cr_srvr_done_no_cert_req_to_key_exch(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_SRVR_DONE, WRITE_TRAN_CONTINUE, TLS_ST_CW_KEY_EXCH);
}

static void test_write_cr_srvr_done_cert_req_to_cert(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CR_SRVR_DONE, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT);
}

static void test_write_cw_cert_to_key_exch(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_CERT, WRITE_TRAN_CONTINUE, TLS_ST_CW_KEY_EXCH);
}

static void test_write_cw_key_exch_cert_req_to_cert_vrfy(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CW_KEY_EXCH, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT_VRFY);
}

static void test_write_cw_key_exch_no_cert_req_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_KEY_EXCH, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cw_key_exch_skip_cert_verify_flag_to_change(
    void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    s.s3.flags = TLS1_FLAGS_SKIP_CERT_VERIFY;
    WRITE_TRAN(TLS_ST_CW_KEY_EXCH, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cw_cert_vrfy_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_CERT_VRFY, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cw_change_hrr_pending_to_clnt_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hello_retry_request = SSL_HRR_PENDING;
    WRITE_TRAN(TLS_ST_CW_CHANGE, WRITE_TRAN_CONTINUE, TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cw_change_early_data_to_early_data(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.early_data_state = SSL_EARLY_DATA_CONNECTING;
    WRITE_TRAN(TLS_ST_CW_CHANGE, WRITE_TRAN_CONTINUE, TLS_ST_EARLY_DATA);
}

static void test_write_cw_change_to_finished(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_CHANGE, WRITE_TRAN_CONTINUE, TLS_ST_CW_FINISHED);
}

#if !defined(OPENSSL_NO_NEXTPROTONEG)
static void test_write_cw_change_npn_to_next_proto(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.s3.npn_seen = 1;
    WRITE_TRAN(TLS_ST_CW_CHANGE, WRITE_TRAN_CONTINUE, TLS_ST_CW_NEXT_PROTO);
}

static void test_write_cw_next_proto_to_finished(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_NEXT_PROTO, WRITE_TRAN_CONTINUE, TLS_ST_CW_FINISHED);
}
#endif

static void test_write_cw_finished_resume_to_ok(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    WRITE_TRAN(TLS_ST_CW_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cw_finished_full_finishes(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_FINISHED, WRITE_TRAN_FINISHED, TLS_ST_CW_FINISHED);
}

static void test_write_cr_finished_resume_to_change(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.hit = 1;
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cr_finished_full_to_ok(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cr_hello_req_reneg_denied_to_ok(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ssl3_renegotiate_check(&s.ssl, 1, 0);
    WRITE_TRAN(TLS_ST_CR_HELLO_REQ, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cr_hello_req_reneg_allowed_to_clnt_hello(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ssl3_renegotiate_check(&s.ssl, 1, 1);
    expect_tls_setup_handshake(&s, 1);
    WRITE_TRAN(TLS_ST_CR_HELLO_REQ, WRITE_TRAN_CONTINUE, TLS_ST_CW_CLNT_HELLO);
}

static void test_write_cr_hello_req_setup_fail(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    expect_ssl3_renegotiate_check(&s.ssl, 1, 1);
    expect_tls_setup_handshake(&s, 0);
    WRITE_TRAN(TLS_ST_CR_HELLO_REQ, WRITE_TRAN_ERROR, TLS_ST_CR_HELLO_REQ);
}

static void test_write_bogus_state_fatal(void **state)
{
    INIT_TLS12(s, ctx, cipher);
    s.statem.hand_state = TLS_ST_SR_END_OF_EARLY_DATA;
    expect_ossl_statem_fatal(&s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    assert_int_equal(
        ossl_statem_client_write_transition(&s), WRITE_TRAN_ERROR);
}

static void test_write_cr_cert_req_tls13_pha_to_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.post_handshake_auth = SSL_PHA_REQUESTED;
    WRITE_TRAN(TLS_ST_CR_CERT_REQ, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_write_cr_cert_req_tls13_pha_to_comp_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.post_handshake_auth = SSL_PHA_REQUESTED;
    s.ext.client_cert_type = TLSEXT_cert_type_x509;
    s.ext.compress_certificate_from_peer[0] = TLSEXT_comp_cert_zlib;
    WRITE_TRAN(TLS_ST_CR_CERT_REQ, WRITE_TRAN_CONTINUE, TLS_ST_CW_COMP_CERT);
}
#endif

static void test_write_cr_cert_req_tls13_after_close_notify_to_ok(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.shutdown = SSL_SENT_SHUTDOWN;
    WRITE_TRAN(TLS_ST_CR_CERT_REQ, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cr_cert_req_tls13_unsolicited_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_OPENSSL_die();
    expect_ossl_statem_fatal(&s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    WRITE_TRAN(TLS_ST_CR_CERT_REQ, WRITE_TRAN_ERROR, TLS_ST_CR_CERT_REQ);
}

static void test_write_cr_finished_tls13_early_data_to_pending_end(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.early_data_state = SSL_EARLY_DATA_WRITE_RETRY;
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE,
        TLS_ST_PENDING_EARLY_DATA_END);
}

static void test_write_cr_finished_tls13_compat_to_change(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.options = SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_CW_CHANGE);
}

static void test_write_cr_finished_tls13_no_cert_req_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_CW_FINISHED);
}

static void test_write_cr_finished_tls13_cert_req_to_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_write_cr_finished_tls13_cert_req_to_comp_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    s.ext.client_cert_type = TLSEXT_cert_type_x509;
    s.ext.compress_certificate_from_peer[0] = TLSEXT_comp_cert_zlib;
    WRITE_TRAN(TLS_ST_CR_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_CW_COMP_CERT);
}
#endif

static void test_write_pending_early_data_end_to_eoed(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.ext.early_data = SSL_EARLY_DATA_ACCEPTED;
    WRITE_TRAN(TLS_ST_PENDING_EARLY_DATA_END, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_END_OF_EARLY_DATA);
}

static void test_write_pending_early_data_end_no_eoed_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_PENDING_EARLY_DATA_END, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_FINISHED);
}

static void test_write_cw_eoed_no_cert_req_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_END_OF_EARLY_DATA, WRITE_TRAN_CONTINUE,
        TLS_ST_CW_FINISHED);
}

static void test_write_cw_change_tls13_cert_req_to_cert(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CW_CHANGE, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT);
}

static void test_write_cw_cert_tls13_with_cert_to_cert_vrfy(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CW_CERT, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT_VRFY);
}

static void test_write_cw_cert_tls13_empty_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 2;
    WRITE_TRAN(TLS_ST_CW_CERT, WRITE_TRAN_CONTINUE, TLS_ST_CW_FINISHED);
}

#ifndef OPENSSL_NO_COMP_ALG
static void test_write_cw_comp_cert_tls13_with_cert_to_cert_vrfy(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.s3.tmp.cert_req = 1;
    WRITE_TRAN(TLS_ST_CW_COMP_CERT, WRITE_TRAN_CONTINUE, TLS_ST_CW_CERT_VRFY);
}
#endif

static void test_write_cw_cert_vrfy_tls13_to_finished(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_CERT_VRFY, WRITE_TRAN_CONTINUE, TLS_ST_CW_FINISHED);
}

static void test_write_cr_key_update_tls13_to_ok(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_KEY_UPDATE, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cw_key_update_tls13_to_ok(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_KEY_UPDATE, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cr_session_ticket_tls13_to_ok(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CR_SESSION_TICKET, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_cw_finished_tls13_to_ok(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    WRITE_TRAN(TLS_ST_CW_FINISHED, WRITE_TRAN_CONTINUE, TLS_ST_OK);
}

static void test_write_ok_tls13_no_key_update_finishes(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.key_update = SSL_KEY_UPDATE_NONE;
    WRITE_TRAN(TLS_ST_OK, WRITE_TRAN_FINISHED, TLS_ST_OK);
}

static void test_write_ok_tls13_key_update_pending_to_key_update(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    s.key_update = SSL_KEY_UPDATE_NOT_REQUESTED;
    WRITE_TRAN(TLS_ST_OK, WRITE_TRAN_CONTINUE, TLS_ST_CW_KEY_UPDATE);
}

static void test_write_bogus_state_tls13_fatal(void **state)
{
    INIT_TLS13(s, ctx, cipher);
    expect_ossl_statem_fatal(&s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
    s.statem.hand_state = (OSSL_HANDSHAKE_STATE)0xBAD;
    assert_int_equal(
        ossl_statem_client_write_transition(&s), WRITE_TRAN_ERROR);
}

int main(void)
{
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_read_cw_clnt_hello_to_srvr_hello),
        cmocka_unit_test(test_read_cw_clnt_hello_dtls_to_hello_verify),
        cmocka_unit_test(test_read_cw_clnt_hello_hello_verify_rejected_in_tls),
        cmocka_unit_test(test_read_cw_clnt_hello_bogus_mt_fatal),
        cmocka_unit_test(test_read_early_data_to_srvr_hello),
        cmocka_unit_test(test_read_early_data_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_srvr_hello_full_to_cert),
        cmocka_unit_test(test_read_cr_srvr_hello_resume_ticket_expected),
        cmocka_unit_test(test_read_cr_srvr_hello_resume_no_ticket_to_change),
        cmocka_unit_test(test_read_cr_srvr_hello_resume_unexpected_ccs_fatal),
        cmocka_unit_test(test_read_cr_srvr_hello_resume_unexpected_nst_fatal),
        cmocka_unit_test(test_read_cr_srvr_hello_dtls_to_hello_verify),
        cmocka_unit_test(test_read_cr_srvr_hello_anon_ske_expected),
        cmocka_unit_test(test_read_cr_srvr_hello_anon_psk_optional_ske),
        cmocka_unit_test(test_read_cr_srvr_hello_anon_no_ske_to_done),
        cmocka_unit_test(test_read_cr_srvr_hello_anon_cert_req_rejected),
        cmocka_unit_test(test_read_cr_srvr_hello_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_to_cert_status),
        cmocka_unit_test(test_read_cr_cert_status_not_expected_falls_through_to_ske),
        cmocka_unit_test(test_read_cr_cert_no_ske_to_cert_req),
        cmocka_unit_test(test_read_cr_cert_no_ske_to_done),
        cmocka_unit_test(test_read_cr_cert_ske_expected_but_other_fatal),
        cmocka_unit_test(test_read_cr_cert_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_status_to_ske),
        cmocka_unit_test(test_read_cr_cert_status_to_cert_req),
        cmocka_unit_test(test_read_cr_cert_status_to_done),
        cmocka_unit_test(test_read_cr_cert_status_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_key_exch_to_cert_req),
        cmocka_unit_test(test_read_cr_key_exch_to_done),
        cmocka_unit_test(test_read_cr_key_exch_anon_cert_req_rejected),
        cmocka_unit_test(test_read_cr_key_exch_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_req_to_done),
        cmocka_unit_test(test_read_cr_cert_req_bogus_mt_fatal),
        cmocka_unit_test(test_read_cw_finished_ticket_expected_to_nst),
        cmocka_unit_test(test_read_cw_finished_no_ticket_to_change),
        cmocka_unit_test(test_read_cw_finished_ticket_expected_unexpected_ccs_fatal),
        cmocka_unit_test(test_read_cw_finished_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_session_ticket_to_change),
        cmocka_unit_test(test_read_cr_session_ticket_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_change_to_finished),
        cmocka_unit_test(test_read_cr_change_bogus_mt_fatal),
        cmocka_unit_test(test_read_ok_to_hello_req),
        cmocka_unit_test(test_read_ok_bogus_mt_fatal),
        cmocka_unit_test(test_read_cw_clnt_hello_tls13_to_srvr_hello),
        cmocka_unit_test(test_read_cw_clnt_hello_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_srvr_hello_tls13_to_encrypted_extensions),
        cmocka_unit_test(test_read_cr_srvr_hello_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_ee_resume_to_finished),
        cmocka_unit_test(test_read_cr_ee_full_to_cert_req),
        cmocka_unit_test(test_read_cr_ee_full_to_cert),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_read_cr_ee_full_to_comp_cert),
        cmocka_unit_test(test_read_cr_ee_full_comp_cert_not_sent_fatal),
#endif
        cmocka_unit_test(test_read_cr_ee_resume_unexpected_cert_fatal),
        cmocka_unit_test(test_read_cr_ee_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_req_tls13_to_cert),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_read_cr_cert_req_tls13_to_comp_cert),
#endif
        cmocka_unit_test(test_read_cr_cert_req_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_tls13_to_cert_vrfy),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_read_cr_comp_cert_tls13_to_cert_vrfy),
#endif
        cmocka_unit_test(test_read_cr_cert_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_read_cr_cert_vrfy_tls13_to_finished),
        cmocka_unit_test(test_read_cr_cert_vrfy_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_read_ok_tls13_to_session_ticket),
        cmocka_unit_test(test_read_ok_tls13_to_key_update),
        cmocka_unit_test(test_read_ok_tls13_pha_cert_req),
        cmocka_unit_test(test_read_ok_tls13_pha_digest_restore_fail),
        cmocka_unit_test(test_read_ok_tls13_cert_req_no_pha_fatal),
        cmocka_unit_test(test_read_ok_tls13_bogus_mt_fatal),
        cmocka_unit_test(test_write_ok_no_renegotiate_finishes),
        cmocka_unit_test(test_write_ok_renegotiate_to_clnt_hello),
        cmocka_unit_test(test_write_before_to_clnt_hello),
        cmocka_unit_test(test_write_cw_clnt_hello_no_early_data_finishes),
        cmocka_unit_test(test_write_cw_clnt_hello_early_data_to_change),
        cmocka_unit_test(test_write_cw_clnt_hello_early_data_no_compat_to_early_data),
        cmocka_unit_test(test_write_cr_srvr_hello_compat_to_change),
        cmocka_unit_test(test_write_cr_srvr_hello_compat_after_early_data_to_clnt_hello),
        cmocka_unit_test(test_write_cr_srvr_hello_no_compat_to_clnt_hello),
        cmocka_unit_test(test_write_early_data_finishes),
        cmocka_unit_test(test_write_dtls_hello_verify_to_clnt_hello),
        cmocka_unit_test(test_write_cr_srvr_done_no_cert_req_to_key_exch),
        cmocka_unit_test(test_write_cr_srvr_done_cert_req_to_cert),
        cmocka_unit_test(test_write_cw_cert_to_key_exch),
        cmocka_unit_test(test_write_cw_key_exch_cert_req_to_cert_vrfy),
        cmocka_unit_test(test_write_cw_key_exch_no_cert_req_to_change),
        cmocka_unit_test(test_write_cw_key_exch_skip_cert_verify_flag_to_change),
        cmocka_unit_test(test_write_cw_cert_vrfy_to_change),
        cmocka_unit_test(test_write_cw_change_hrr_pending_to_clnt_hello),
        cmocka_unit_test(test_write_cw_change_early_data_to_early_data),
        cmocka_unit_test(test_write_cw_change_to_finished),
#if !defined(OPENSSL_NO_NEXTPROTONEG)
        cmocka_unit_test(test_write_cw_change_npn_to_next_proto),
        cmocka_unit_test(test_write_cw_next_proto_to_finished),
#endif

        cmocka_unit_test(test_write_cw_finished_resume_to_ok),
        cmocka_unit_test(test_write_cw_finished_full_finishes),
        cmocka_unit_test(test_write_cr_finished_resume_to_change),
        cmocka_unit_test(test_write_cr_finished_full_to_ok),
        cmocka_unit_test(test_write_cr_hello_req_reneg_denied_to_ok),
        cmocka_unit_test(test_write_cr_hello_req_reneg_allowed_to_clnt_hello),
        cmocka_unit_test(test_write_cr_hello_req_setup_fail),
        cmocka_unit_test(test_write_bogus_state_fatal),
        cmocka_unit_test(test_write_cr_cert_req_tls13_pha_to_cert),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_write_cr_cert_req_tls13_pha_to_comp_cert),
#endif
        cmocka_unit_test(test_write_cr_cert_req_tls13_after_close_notify_to_ok),
        cmocka_unit_test(test_write_cr_cert_req_tls13_unsolicited_fatal),
        cmocka_unit_test(test_write_cr_finished_tls13_early_data_to_pending_end),
        cmocka_unit_test(test_write_cr_finished_tls13_compat_to_change),
        cmocka_unit_test(test_write_cr_finished_tls13_no_cert_req_to_finished),
        cmocka_unit_test(test_write_cr_finished_tls13_cert_req_to_cert),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_write_cr_finished_tls13_cert_req_to_comp_cert),
#endif
        cmocka_unit_test(test_write_pending_early_data_end_to_eoed),
        cmocka_unit_test(test_write_pending_early_data_end_no_eoed_to_finished),
        cmocka_unit_test(test_write_cw_eoed_no_cert_req_to_finished),
        cmocka_unit_test(test_write_cw_change_tls13_cert_req_to_cert),
        cmocka_unit_test(test_write_cw_cert_tls13_with_cert_to_cert_vrfy),
        cmocka_unit_test(test_write_cw_cert_tls13_empty_to_finished),
#ifndef OPENSSL_NO_COMP_ALG
        cmocka_unit_test(test_write_cw_comp_cert_tls13_with_cert_to_cert_vrfy),
#endif
        cmocka_unit_test(test_write_cw_cert_vrfy_tls13_to_finished),
        cmocka_unit_test(test_write_cr_key_update_tls13_to_ok),
        cmocka_unit_test(test_write_cw_key_update_tls13_to_ok),
        cmocka_unit_test(test_write_cr_session_ticket_tls13_to_ok),
        cmocka_unit_test(test_write_cw_finished_tls13_to_ok),
        cmocka_unit_test(test_write_ok_tls13_no_key_update_finishes),
        cmocka_unit_test(test_write_ok_tls13_key_update_pending_to_key_update),
        cmocka_unit_test(test_write_bogus_state_tls13_fatal),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
