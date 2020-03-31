/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef ENROLLMENT_CLIENT_H
#define ENROLLMENT_CLIENT_H

/*
 * Struct that defines the enrollment certificate configuration
 * Client Enrollment methods:
 * 1. Simple verification (only chipers needed)
 * 2. Password (uses password param)
 * 3. Manger Verificatiion (uses ca_cert param) 
 * 4. Manger and Agent Verification (uses ca_cert, agent_cert and agent_key params)
 * @param ciphters chipers string (default DEFAULT_CIPHERS)
 * @param agent_cert Agent Certificate (null if not used)
 * @param agent_key Agent Key (null if not used)
 * @param ca_cert CA Certificate to verificate server (null if not used)
 */
typedef struct _CERTIFICATE_CFG {
    const char *ciphers;
    const char *password;
    const char *agent_cert;
    const char *agent_key;
    const char *ca_cert;
} CERTIFICATE_CFG;

/**
 * Starts an SSL conection with the manger instance
 * @param ssl Pointer to the ssl conection that will hold the connection if successfull
 * @param hostname ip adress of the server or hostname in case of CA Cert verification
 * @param port port of the server
 * @param cfg Certificate configuration
 * @param auto_method 0 for TLS v1.2 only (Default)
 *                    1 for Auto negotiate the most secure common SSL/TLS method with the client.
 * @return  0 if successfull
 *         -1 on invalid configuration
 *         -2 connection error
 */
int start_enrollemnt_connection(
        SSL* ssl,
        const char* hostname, 
        const char* port, 
        const CERTIFICATE_CFG* cfg, 
        const int auto_method
);

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
void send_enrollment_message(
        const SSL *ssl,
        const char* hostname,
        char* agent_name,
        const char* password,
        const char* centralized_group,
        const char* sender_ip,
);

#endif