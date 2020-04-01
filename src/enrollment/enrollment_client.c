/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "enrollment_client.h"
#include "os_auth/check_cert.h"
#include "os_auth/auth.h"
#include "os_net/os_net.h"
#include "shared.h"


static void _verify_ca_certicificate(const SSL *ssl, const char *ca_cert, const char *hostname);
static void _concat_group(char *buff, const char* centralized_group);
static int _concat_src_ip(char *buff, const char* sender_ip);

int start_enrollemnt_connection(
    SSL* ssl,
    const char* hostname, 
    const int port,
    const CERTIFICATE_CFG* cfg, 
    const int auto_method) 
{
    const char *ip_address = OS_GetHost(hostname, 3);
    /* Translate hostname to an ip_adress */
    if (!ip_address) {
        merror("Could not resolve hostname: %s\n", hostname);
        return -1;
    }

    /* Start SSL */
    SSL_CTX *ctx = os_ssl_keys(0, NULL, cfg->ciphers, cfg->agent_cert, cfg->agent_key, cfg->ca_cert, auto_method);
    if (!ctx) {
        merror("SSL error. Exiting.");
        return -1;
    }

    /* Connect via TCP */
    int sock = OS_ConnectTCP((u_int16_t) port, ip_address, 0);
    if (sock <= 0) {
        merror("Unable to connect to %s:%d", ip_address, port);
        return -1;
    }

    /* Connect the SSL socket */
    ssl = SSL_new(ctx);
    BIO * sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    ERR_clear_error();
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        merror("SSL error (%d). Connection refused by the manager. Maybe the port specified is incorrect. Exiting.", SSL_get_error(ssl, ret));
        ERR_print_errors_fp(stderr);  // This function empties the error queue
        return -2;
    }

    minfo("Connected to %s:%d", ip_address, port);

    _verify_ca_certicificate(ssl, cfg->ca_cert, hostname);

    return 0;
}

int send_enrollment_message(
        SSL *ssl,
        char* agent_name,
        const char* password,
        const char* centralized_group,
        const char* sender_ip
) {
    /* agent_name extraction */
    if (agent_name == NULL) {
        char *lhostname;
        os_malloc(513, lhostname);
        lhostname[512] = '\0';
        if (gethostname(lhostname, 512 - 1) != 0) {
            merror("Unable to extract hostname. Custom agent name not set.");
            return -1;
        }
        agent_name = lhostname;
    }
    minfo("Using agent name as: %s", agent_name);

    /* Message formation */
    char *buf;
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    if (password) {
        snprintf(buf, 2048, "OSSEC PASS: %s OSSEC A:'%s'", password, agent_name);
    } else {
        snprintf(buf, 2048, "OSSEC A:'%s'", agent_name);
    }

    if(centralized_group){
        _concat_group(buf, centralized_group);
    }

    if(_concat_src_ip(buf, sender_ip)) {
        os_free(buf);
        return -1;
    }

    /* Append new line character */
    strcat(buf,"\n");
    int ret = SSL_write(ssl, buf, strlen(buf));
    if (ret < 0) {
        merror("SSL write error (unable to send message.)");
        ERR_print_errors_fp(stderr);
        os_free(buf);
        return -1;
    }
    minfo("Request sent to manager");

    os_free(buf);
    return 0;
}

/**
 * Verifies the manager's ca certificate. Displays a warning message if it does not match
 * @param ssl SSL conection established with the manager
 * @param ca_cert cerificate to verify
 * @param hostname 
 * */
static void _verify_ca_certicificate(const SSL *ssl, const char *ca_cert, const char *hostname) {
    if (ca_cert) {
        minfo("Verifying manager's certificate");
        if (check_x509_cert(ssl, hostname) != VERIFY_TRUE) {
            merror("Unable to verify server certificate.");
        }
    }
    else {
        mwarn("Registering agent to unverified manager.");
    }
}


static void _concat_group(char *buff, const char* centralized_group) {
    char * opt_buf = NULL;
    os_calloc(OS_SIZE_65536, sizeof(char), opt_buf);
    snprintf(opt_buf,OS_SIZE_65536," G:'%s'",centralized_group);
    strncat(buff,opt_buf,OS_SIZE_65536);
    free(opt_buf);
}

/**
 * Concats the IP part of the enrollment message
 * @param buff buffer where the IP section will be concatenated
 * @param sender_ip Sender IP, if null it will be filled with "src"
 * @return 0 on success
 *        -1 if ip is invalid 
 */
static int _concat_src_ip(char *buff, const char* sender_ip) {
    if(sender_ip){
		/* Check if this is strictly an IP address using a regex */
		if (OS_IsValidIP(sender_ip, NULL))
		{
			char opt_buf[256] = {0};
			snprintf(opt_buf,254," IP:'%s'",sender_ip);
			strncat(buff,opt_buf,254);
		} else {
			merror("Invalid IP address provided for sender IP.");
			return -1;
		}
    } else {
        char opt_buf[10] = {0};
        snprintf(opt_buf,10," IP:'src'");
        strncat(buff,opt_buf,10);
    }

    return 0;
}