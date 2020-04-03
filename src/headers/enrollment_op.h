/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file enrollment_op.h
 * @author Nicolas Papp (nicolas.papp@wazuh.com)
 * @date 4 April 2020
 * @brief Library that handles the enrollment process of an agent
 *
 * Wazuh agents need to register to a manager before being able to start sending messages
 * There are several way of registering according to manager's configuration
 * This library receives a enrollment configuration and target especification and registers to the 
 * manager or shows several messages in case of failure
 * For details on enrollment process @see https://documentation.wazuh.com/3.12/user-manual/registering/
 */
#ifndef ENROLLMENT_CLIENT_H
#define ENROLLMENT_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#define ENROLLMENT_WRONG_CONFIGURATION -1
#define ENROLLMENT_CONNECTION_FAILURE -2

/**
 * @brief Struct that defines the connection target
 * */
typedef struct _enrollment_target_cfg {
    char *manager_name;       /**> Manager's direction or ip address */
    int port;                 /**> Manager's port                     */
    char *agent_name;         /**> (optional) Name of the agent. In case of NULL enrollment message will send local hostname */
    char *centralized_group;  /**> (optional) In case the agent belong to a group */
    char *sender_ip;          /**> (optional) IP adress or CIDR of the agent. In case of null the manager will use the source ip */
} w_enrollment_target_cfg;

/**
 * @brief Certificate configurations 
 * 
 * Struct that defines the enrollment certificate configuration
 * Client Enrollment methods:
 * 1. Simple verification (only chipers needed)
 * 2. Password (uses authpass param)
 * 3. Manager Verificatiion (uses ca_cert param) 
 * 4. Manager and Agent Verification (uses agent_cert and agent_key params)
 */
typedef struct _enrollment_cert_cfg {
    char *ciphers;     /**> chipers string (default DEFAULT_CIPHERS) */
    char *authpass;    /**> for password verification */
    char *agent_cert;  /**> Agent Certificate (null if not used) */
    char *agent_key;   /**> Agent Key (null if not used) */
    char *ca_cert;     /**> CA Certificate to verificate server (null if not used) */
    int auto_method:1; /**> 0 for TLS v1.2 only (Default), 1 for Auto negotiate the most secure common SSL/TLS method with the client. */
} w_enrollment_cert_cfg; 

/**
 * @brief Strcture that handles all the enrollment configuration
 * */
typedef struct _enrollment_ctx {
    const w_enrollment_target_cfg *target_cfg;  /**> for details @see _enrollment_target_cfg */
    const w_enrollment_cert_cfg *cert_cfg;      /**> for details @see _enrollment_cert_cfg */
    SSL *ssl;                                   /**> will hold the connection instance with the manager */
    unsigned int enabled:1;
} w_enrollment_ctx;

/**
 * Initializes parameters of an w_enrollment_ctx structure based
 * on a target and certificate configurations
 * */
w_enrollment_ctx * w_enrollment_init(const w_enrollment_target_cfg *target, const w_enrollment_cert_cfg *cert);

/**
 * Frees parameers of an w_enrollment_ctx structure
 * target_cfg and cert_cfg should be freed on their own since there are constant pointers
 * */
void w_enrollment_destroy(w_enrollment_ctx *cfg);

/**
 * Starts an SSL conection with the manger instance
 * @param cfg Enrollment configuration sturcture
 *      @see w_enrollment_ctx for details
 * @return  socket_id >= 0 if successfull
 *         ENROLLMENT_WRONG_CONFIGURATION(-1) on invalid configuration
 *         ENROLLMENT_CONNECTION_FAILURE(-2) connection error
 */
int w_enrollment_connect(w_enrollment_ctx *cfg);

/**
 * Sends initial enrollment message. Must call 
 *      w_enrollment_process_response to obtain response
 * @param cfg Enrollment configuration sturcture
 *      @see w_enrollment_ctx for details
 * @return   0 if message is sent successfully
 *          -1 if message cannot be sent
 */
int w_enrollment_send_message(w_enrollment_ctx *cfg);


int w_enrollment_process_response(w_enrollment_ctx *cfg);


/**
 * Stores entry string to the file containing the agent keys
 * @param keys string cointaining the following information:
 *      ENTRY_ID AGENT_NAME IP KEY
 * @return 0 if key is store successfully 
 *        -1 if there is an error
 * */
int w_enrollment_store_key_entry(const char* keys);
#endif
