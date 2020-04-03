/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_auth/check_cert.h"
#include "os_auth/auth.h"
#include "os_net/os_net.h"
#include "shared.h"

#ifdef UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

static void _verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname);
static void _concat_group(char *buff, const char* centralized_group);
static int _concat_src_ip(char *buff, const char* sender_ip);
static void _process_agent_key(char *buffer);

/* Constants */
static const int ENTRY_ID = 0;
static const int ENTRY_NAME = 1;
static const int ENTRY_IP = 2;
static const int ENTRY_KEY = 3; 

w_enrollment_ctx * w_enrollment_init(const w_enrollment_target_cfg *target, const w_enrollment_cert_cfg *cert) {
    w_enrollment_ctx *cfg;
    os_malloc(sizeof(w_enrollment_ctx), cfg);
    // Copy constructor for const parameters
    w_enrollment_ctx init = {
        .target_cfg = target,
        .cert_cfg = cert
    };
    memcpy(cfg, &init, sizeof(w_enrollment_ctx));
    cfg->enabled = 1;
    cfg->ssl = NULL;
    return cfg;
}

void w_enrollment_destroy(w_enrollment_ctx *cfg) {
    os_free(cfg);
}

int w_enrollment_connect(w_enrollment_ctx *cfg) 
{
    const char *ip_address = OS_GetHost(cfg->target_cfg->manager_name, 3);
    /* Translate hostname to an ip_adress */
    if (!ip_address) {
        merror("Could not resolve hostname: %s\n", cfg->target_cfg->manager_name);
        return ENROLLMENT_WRONG_CONFIGURATION;
    }

    /* Start SSL */
    SSL_CTX *ctx = os_ssl_keys(0, NULL, cfg->cert_cfg->ciphers, 
        cfg->cert_cfg->agent_cert, cfg->cert_cfg->agent_key, cfg->cert_cfg->ca_cert, cfg->cert_cfg->auto_method);
    if (!ctx) {
        merror("Could not set up SSL connection! Check ceritification configuration.");
        return ENROLLMENT_WRONG_CONFIGURATION;
    }

    /* Connect via TCP */
    int sock = OS_ConnectTCP((u_int16_t) cfg->target_cfg->port, ip_address, 0);
    if (sock <= 0) {
        merror("Unable to connect to %s:%d", ip_address, cfg->target_cfg->port);
        SSL_CTX_free(ctx);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    /* Connect the SSL socket */
    cfg->ssl = SSL_new(ctx);
    BIO * sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(cfg->ssl, sbio, sbio);

    ERR_clear_error();
    int ret = SSL_connect(cfg->ssl);
    if (ret <= 0) {
        merror("SSL error (%d). Connection refused by the manager. Maybe the port specified is incorrect. Exiting.", SSL_get_error(cfg->ssl, ret));
        ERR_print_errors_fp(stderr);  // This function empties the error queue
        SSL_CTX_free(ctx);
        return ENROLLMENT_CONNECTION_FAILURE;
    }

    minfo("Connected to %s:%d", ip_address, cfg->target_cfg->port);

    _verify_ca_certificate(cfg->ssl, cfg->cert_cfg->ca_cert, cfg->target_cfg->manager_name);

    SSL_CTX_free(ctx);
    return sock;
}

int w_enrollment_send_message(w_enrollment_ctx *cfg) {
    char *lhostname = NULL;
    /* agent_name extraction */
    if (cfg->target_cfg->agent_name == NULL) {
        os_malloc(513, lhostname);
        lhostname[512] = '\0';
        if (gethostname(lhostname, 512 - 1) != 0) {
            merror("Unable to extract hostname. Custom agent name not set.");
            os_free(lhostname);
            return -1;
        }
    } else {
        lhostname = cfg->target_cfg->agent_name;
    }
    minfo("Using agent name as: %s", lhostname);

    /* Message formation */
    char *buf;
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    if (cfg->cert_cfg->authpass) {
        snprintf(buf, 2048, "OSSEC PASS: %s OSSEC A:'%s'", cfg->cert_cfg->authpass, lhostname);
    } else {
        snprintf(buf, 2048, "OSSEC A:'%s'", lhostname);
    }

    if(cfg->target_cfg->centralized_group){
        _concat_group(buf, cfg->target_cfg->centralized_group);
    }

    if(_concat_src_ip(buf, cfg->target_cfg->sender_ip)) {
        os_free(buf);
        os_free(lhostname);
        return -1;
    }

    /* Append new line character */
    strcat(buf,"\n");
    int ret = SSL_write(cfg->ssl, buf, strlen(buf));
    if (ret < 0) {
        merror("SSL write error (unable to send message.)");
        ERR_print_errors_fp(stderr);
        os_free(buf);
        os_free(lhostname);
        return -1;
    }
    minfo("Request sent to manager");

    os_free(buf);
    os_free(lhostname);
    return 0;
}

int w_enrollment_process_response(w_enrollment_ctx *cfg) {
    char *buf;
    int ret;
    os_calloc(OS_SIZE_65536 + OS_SIZE_4096 + 1, sizeof(char), buf);
    buf[OS_SIZE_65536 + OS_SIZE_4096] = '\0';

    minfo("Waiting for manager reply");

    while(ret = SSL_read(cfg->ssl, buf, OS_SIZE_65536 + OS_SIZE_4096), ret > 0) {
        buf[ret] = '\0';
        if (strlen(buf) > 7 && !strncmp(buf, "ERROR: ", 7)) { 
            // Process error message
            char *tmpbuf;
            tmpbuf = strchr(buf, ' ');
            tmpbuf++;
            if (tmpbuf && tmpbuf[0] != '\0') {
                merror("%s (from manager)", tmpbuf);
            }
        } else if (strncmp(buf, "OSSEC K:'", 9) == 0) {
            minfo("Received response with agent key");
            _process_agent_key(buf);
        }
    }
    return 0;

}

int w_enrollment_store_key_entry(const char* keys) {
    FILE *fp;
    umask(0026);
    fp = fopen(KEYSFILE_PATH, "w");

    if (!fp) {
        merror("Unable to open key file: %s", KEYSFILE_PATH);
        return -1;
    }
    fprintf(fp, "%s\n", keys);
    fclose(fp);
    return 0;
}

/**
 * Process string that contains agent information.
 * If the information is correct stores the key in the agent keys file
 * @param buffer
 * */
static void _process_agent_key(char *buffer) {
    char *keys = &buffer[9]; //Start of the information
    char *tmpstr = strchr(keys, '\'');
    if (!tmpstr) {
        // No end of string found
        merror("Invalid keys format received.");
        return;
    }
    *tmpstr = '\0';
    char **entrys = OS_StrBreak(' ', keys, 4);
    if (OS_IsValidID(entrys[ENTRY_ID]) && OS_IsValidName(entrys[ENTRY_NAME]) &&
            OS_IsValidIP(entrys[ENTRY_IP], NULL) && !OS_IsValidName(entrys[ENTRY_KEY])) {
        if( !w_enrollment_store_key_entry(keys) ) {
            // Key was able to store
            minfo("Valid key created. Finished.");
        }
    } else {
        merror("One of the received key parameters does not have a valid format.");
        return;
    }
}

/**
 * Verifies the manager's ca certificate. Displays a warning message if it does not match
 * @param ssl SSL conection established with the manager
 * @param ca_cert cerificate to verify
 * @param hostname 
 * */
static void _verify_ca_certificate(const SSL *ssl, const char *ca_cert, const char *hostname) {
    assert(ssl != NULL);
    
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
    assert(buff != NULL); // buff should not be NULL.
    assert(centralized_group != NULL); 

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
    assert(buff != NULL); // buff should not be NULL.

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
