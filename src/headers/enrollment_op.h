/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef ENROLLMENT_CLIENT_H
#define ENROLLMENT_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#define ENROLLMENT_WRONG_CONFIGURATION -1
#define ENROLLMENT_CONNECTION_FAILURE -2

/**
 * Struct that defines the connection target
 * @param manager_name Manager's direction or ip address
 * @param port Manager's port
 * @param agent_name (optional) Name of the agent. In case of NULL it will be set by enrollment message 
 * to the local hostname
 * @param centralized_group (optional) In case the agent belong to a group
 * @param sender_ip (optional) IP adress or CIDR of the agent. In case of null the manager will use the source ip 
 * */
typedef struct _enrollment_target_cfg {
    char *manager_name;
    int port;
    char *agent_name;
    char *centralized_group;
    char *sender_ip;
} _enrollment_target_cfg;

/**
 * Struct that defines the enrollment certificate configuration
 * Client Enrollment methods:
 * 1. Simple verification (only chipers needed)
 * 2. Password (uses authpass param)
 * 3. Manager Verificatiion (uses ca_cert param) 
 * 4. Manager and Agent Verification (uses agent_cert and agent_key params)
 * @param ciphters chipers string (default DEFAULT_CIPHERS)
 * @param authpass for password verification
 * @param agent_cert Agent Certificate (null if not used)
 * @param agent_key Agent Key (null if not used)
 * @param ca_cert CA Certificate to verificate server (null if not used)
 * @param auto_method 0 for TLS v1.2 only (Default)
 *                    1 for Auto negotiate the most secure common SSL/TLS method with the client.
 * 
 */
typedef struct _enrollment_cert_cfg {
    char *ciphers;
    char *authpass;
    char *agent_cert;
    char *agent_key;
    char *ca_cert;
    int auto_method;
} _enrollment_cert_cfg; 

/**
 * Strcture that handles all the enrollment configuration
 * @param target_cfg for details @see _enrollment_target_cfg
 * @param cert_cfg for details @see _enrollment_cert_cfg
 * @param ssl will hold the connection instance
 *      with the manager
 * */
typedef struct _enrollment_cfg {
    _enrollment_target_cfg target_cfg;
    _enrollment_cert_cfg cert_cfg;
    SSL *ssl;
} enrollment_cfg;

/**
 * Initializes parameters of an enrollment_cfg structure
 * */
void w_enrollment_init(enrollment_cfg *cfg);

/**
 * Frees parameers of an enrollment_cfg structure
 * */
void w_enrollment_destroy(enrollment_cfg *cfg);

/**
 * Starts an SSL conection with the manger instance
 * @param cfg Enrollment configuration sturcture
 *      @see enrollment_cfg for details
 * @return  socket_id >= 0 if successfull
 *         ENROLLMENT_WRONG_CONFIGURATION(-1) on invalid configuration
 *         ENROLLMENT_CONNECTION_FAILURE(-2) connection error
 */
int w_enrollment_connect(enrollment_cfg *cfg);

/**
 * Sends initial enrollment message
 * @param ssl Pointer to the initialized connection with the manager
 * @param agent_name Agent name. If null local hostname will be used as name and stored in pointer
 * @param password Required password in case the enrollment process requires it
 * @param centralized_group if the agent belongs to a group. If null it asumes it does not belong to any group
 * @param sender_ip set sender IP, if it is null the manager will use the source ip of the message
 * @return   0 if message is sent successfully
 *          -1 if message cannot be sent
 */
int w_enrollment_send_message(
        SSL *ssl,
        char* agent_name,
        const char* password,
        const char* centralized_group,
        const char* sender_ip
);

#endif
