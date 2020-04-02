#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"
#include "enrollment/enrollment_client.h"

extern int _concat_src_ip(char *buff, const char* sender_ip);
extern void _concat_group(char *buff, const char* centralized_group);

/*************** WRAPS ************************/
void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}