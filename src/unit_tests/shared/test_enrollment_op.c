#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "os_auth/check_cert.h"
#include "os_auth/auth.h"

extern int _concat_src_ip(char *buff, const char* sender_ip);
extern void _concat_group(char *buff, const char* centralized_group);
extern void _verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname);

/*************** WRAPS ************************/
void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_OS_IsValidIP(const char *ip_address, os_ip *final_ip) {
    check_expected(ip_address);
    check_expected(final_ip);
    return mock_type(int);
}

int __wrap_check_x509_cert(const SSL *ssl, const char *manager) {
    check_expected_ptr(ssl);
    check_expected(manager);
    return mock_type(int);
}

char *__wrap_OS_GetHost(const char *host, unsigned int attempts) {
    check_expected(host);
    return mock_ptr_type(char *);
}

SSL_CTX *__wrap_os_ssl_keys(int is_server, const char *os_dir, const char *ciphers, const char *cert, const char *key, const char *ca_cert, int auto_method)
{
    check_expected(is_server);
    check_expected(os_dir);
    check_expected(ciphers);
    check_expected(cert);
    check_expected(key);
    check_expected(ca_cert);
    check_expected(auto_method);
    return mock_ptr_type(SSL_CTX *);
}

extern SSL *__real_SSL_new(SSL_CTX *ctx);
SSL *__wrap_SSL_new(SSL_CTX *ctx) {
    check_expected(ctx);
    return mock_ptr_type(SSL *);
}

int __wrap_SSL_connect(SSL *s){
    return mock_type(int);
}

int __wrap_SSL_get_error(const SSL *s, int i)
{
    check_expected(i);
    return mock_type(int);
}

int __wrap_OS_ConnectTCP(u_int16_t _port, const char *_ip, int ipv6)
{
    check_expected(_port);
    check_expected(_ip);
    check_expected(ipv6);
    return mock_type(int);
}

void __wrap_SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) {
    return;    
}

// Setup
int test_setup_concats(void **state) {
    char *buf;
    os_calloc(OS_SIZE_65536, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';
    *state = buf;
    return 0;
}
//Teardown
int test_teardown_concats(void **state) {
    free(*state);
    return 0;
}
/**********************************************/
/************* _concat_src_ip ****************/
void test_concat_src_ip_invalid_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = "256.300.1";
    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string(__wrap__merror, formatted_msg, "Invalid IP address provided for sender IP.");
    int ret = _concat_src_ip(buf, sender_ip);
    assert_int_equal(ret, -1);
}

void test_concat_src_ip_valid_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = "192.168.1.1";
    expect_string(__wrap_OS_IsValidIP, ip_address, sender_ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    int ret = _concat_src_ip(buf, sender_ip);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'192.168.1.1'");
}

void test_concat_src_ip_empty_ip(void **state) {
    char *buf = *state;
    const char* sender_ip = NULL;

    int ret = _concat_src_ip(buf, sender_ip);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, " IP:'src'");
}

void test_concat_src_ip_empty_buff(void **state) {
    expect_assert_failure(_concat_src_ip(NULL, NULL));
}
/**********************************************/
/************* _concat_group ****************/
void test_concat_group_empty_buff(void **state) {
    expect_assert_failure(_concat_group(NULL, "EXAMPLE_GROUP"));
}

void test_concat_group_empty_group(void **state) {
    char *buf = *state;
    expect_assert_failure(_concat_group(buf, NULL));
}

void test_concat_group(void **state) {
    char *buf = *state;
    const char *group = "EXAMPLE_GROUP";
    _concat_group(buf, group);
    assert_string_equal(buf, " G:'EXAMPLE_GROUP'");
}
/**********************************************/
/********** _verify_ca_certificate *************/
void test_verify_ca_certificate_null_connection(void **state) {
    expect_assert_failure(_verify_ca_certificate(NULL, "certificate_path", "hostname"));
}

void test_verify_ca_certificate_no_certificate(void **state) {
    SSL *ssl;
    expect_string(__wrap__mwarn, formatted_msg, "Registering agent to unverified manager.");
    _verify_ca_certificate(ssl, NULL, "hostname");
}

void test_verificy_ca_certificate_invalid_certificate(void **state) {
    SSL *ssl;
    const char *hostname = "hostname";
    expect_value(__wrap_check_x509_cert, ssl, ssl);
    expect_string(__wrap_check_x509_cert, manager, hostname);
    will_return(__wrap_check_x509_cert, VERIFY_FALSE);

    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
    expect_string(__wrap__merror, formatted_msg, "Unable to verify server certificate.");
    _verify_ca_certificate(ssl, "BAD_CERTIFICATE", "hostname");
}

void test_verificy_ca_certificate_valid_certificate(void **state) {
    SSL *ssl;
    const char *hostname = "hostname";
    expect_value(__wrap_check_x509_cert, ssl, ssl);
    expect_string(__wrap_check_x509_cert, manager, hostname);
    will_return(__wrap_check_x509_cert, VERIFY_TRUE);

    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");
    _verify_ca_certificate(ssl, "GOOD_CERTIFICATE", "hostname");
}
/**********************************************/
/********** w_enrollment_init *******/
void test_w_enrollment_init_invalid_hostname(void **state) {
    SSL *ssl = NULL;
    CERTIFICATE_CFG cfg = {0};
    const char *hostname = "invalid_hostname";
    
    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, NULL);
    expect_string(__wrap__merror, formatted_msg, "Could not resolve hostname: invalid_hostname\n");

    int ret = w_enrollment_init(&ssl, hostname, 1234, &cfg, 0);
    assert_int_equal(ret, ENROLLMENT_WRONG_CONFIGURATION);
}

void test_w_enrollment_init_could_not_setup(void **state) {
    SSL *ssl = NULL;
    CERTIFICATE_CFG cfg = {
        .ciphers = DEFAULT_CIPHERS, 
        .agent_cert = "CERT",
        .agent_key = "KEY",
        .ca_cert = "CA_CERT",
    };
    const char *hostname = "invalid_hostname";
    
    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, "127.0.0.1");
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, NULL);

    expect_string(__wrap__merror, formatted_msg, "Could not set up SSL connection! Check ceritification configuration.");
    int ret = w_enrollment_init(&ssl, hostname, 1234, &cfg, 0);
    assert_int_equal(ret, ENROLLMENT_WRONG_CONFIGURATION);
}

void test_w_enrollment_init_socket_error(void **state) {
    SSL *ssl = NULL;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    CERTIFICATE_CFG cfg = {
        .ciphers = DEFAULT_CIPHERS, 
        .agent_cert = "CERT",
        .agent_key = "KEY",
        .ca_cert = "CA_CERT",
    };
    const char *hostname = "invalid_hostname";
    // GetHost
    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, "127.0.0.1");
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, &ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, -1);

    expect_string(__wrap__merror, formatted_msg, "Unable to connect to 127.0.0.1:1234");
    int ret = w_enrollment_init(&ssl, hostname, 1234, &cfg, 0);
    assert_int_equal(ret, ENROLLMENT_CONNECTION_FAILURE);
}

void test_w_enrollment_init_SSL_connect_error(void **state) {
    SSL *ssl = NULL;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    CERTIFICATE_CFG cfg = {
        .ciphers = DEFAULT_CIPHERS, 
        .agent_cert = "CERT",
        .agent_key = "KEY",
        .ca_cert = "CA_CERT",
    };
    const char *hostname = "invalid_hostname";
    // GetHost
    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, "127.0.0.1");
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, 5);
    // Connect SSL
    expect_value(__wrap_SSL_new, ctx, ctx);
    will_return(__wrap_SSL_new, __real_SSL_new);
    will_return(__wrap_SSL_connect, -1);
    
    expect_value(__wrap_SSL_get_error, i, -1);
    will_return(__wrap_SSL_get_error, 100);
    expect_string(__wrap__merror, formatted_msg, "SSL error (100). Connection refused by the manager. Maybe the port specified is incorrect. Exiting.");

    int ret = w_enrollment_init(&ssl, hostname, 1234, &cfg, 0);
    assert_int_equal(ret, ENROLLMENT_CONNECTION_FAILURE);
}

void test_w_enrollment_init_success(void **state) {
    SSL *ssl = NULL;
    SSL_CTX *ctx = get_ssl_context(DEFAULT_CIPHERS, 0);
    CERTIFICATE_CFG cfg = {
        .ciphers = DEFAULT_CIPHERS, 
        .agent_cert = "CERT",
        .agent_key = "KEY",
        .ca_cert = "CA_CERT",
    };
    const char *hostname = "invalid_hostname";
    // GetHost
    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, "127.0.0.1");
    // os_ssl_keys
    expect_value(__wrap_os_ssl_keys, is_server, 0);
    expect_value(__wrap_os_ssl_keys, os_dir, NULL);
    expect_string(__wrap_os_ssl_keys, ciphers, DEFAULT_CIPHERS);
    expect_string(__wrap_os_ssl_keys, cert, "CERT");
    expect_string(__wrap_os_ssl_keys, key, "KEY");
    expect_string(__wrap_os_ssl_keys, ca_cert, "CA_CERT");
    expect_value(__wrap_os_ssl_keys, auto_method, 0);
    will_return(__wrap_os_ssl_keys, ctx);
    // OS_ConnectTCP
    expect_value(__wrap_OS_ConnectTCP, _port, 1234);
    expect_string(__wrap_OS_ConnectTCP, _ip, "127.0.0.1");
    expect_value(__wrap_OS_ConnectTCP, ipv6, 0);
    will_return(__wrap_OS_ConnectTCP, 5);
    // Connect SSL
    expect_value(__wrap_SSL_new, ctx, ctx);
    ssl = __real_SSL_new(ctx);
    will_return(__wrap_SSL_new, ssl);
    will_return(__wrap_SSL_connect, 1);
    
    expect_string(__wrap__minfo, formatted_msg, "Connected to 127.0.0.1:1234");

    // verify_ca_certificate
    expect_value(__wrap_check_x509_cert, ssl, ssl);
    expect_string(__wrap_check_x509_cert, manager, hostname);
    will_return(__wrap_check_x509_cert, VERIFY_TRUE);
    expect_string(__wrap__minfo, formatted_msg, "Verifying manager's certificate");

    int ret = w_enrollment_init(&ssl, hostname, 1234, &cfg, 0);
    assert_int_equal(ret, 5);
}

/**********************************************/
int main()
{
    const struct CMUnitTest tests[] = 
    {
        // _concat_src_ip
        cmocka_unit_test_setup_teardown(test_concat_src_ip_invalid_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_concat_src_ip_valid_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_concat_src_ip_empty_ip, test_setup_concats, test_teardown_concats),
        cmocka_unit_test(test_concat_src_ip_empty_buff),
        // _concat_group
        cmocka_unit_test(test_concat_group_empty_buff),
        cmocka_unit_test_setup_teardown(test_concat_group_empty_group, test_setup_concats, test_teardown_concats),
        cmocka_unit_test_setup_teardown(test_concat_group, test_setup_concats, test_teardown_concats),
        //  _verify_ca_certificate
        cmocka_unit_test(test_verify_ca_certificate_null_connection),
        cmocka_unit_test(test_verify_ca_certificate_no_certificate),
        cmocka_unit_test(test_verificy_ca_certificate_invalid_certificate),
        cmocka_unit_test(test_verificy_ca_certificate_valid_certificate),
        // w_enrollment_init
        cmocka_unit_test(test_w_enrollment_init_invalid_hostname),
        cmocka_unit_test(test_w_enrollment_init_could_not_setup),
        cmocka_unit_test(test_w_enrollment_init_socket_error),
        cmocka_unit_test(test_w_enrollment_init_SSL_connect_error),
        cmocka_unit_test(test_w_enrollment_init_success)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}
