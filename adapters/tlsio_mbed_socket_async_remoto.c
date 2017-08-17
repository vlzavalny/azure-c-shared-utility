// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy_poll.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/tlsio_mbed_socket_async_remoto.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/dns_async.h"
#include "azure_c_shared_utility/socket_async.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/crt_abstractions.h"

typedef struct
{
    unsigned char* bytes;
    size_t size;
    size_t unsent_size;
    ON_SEND_COMPLETE on_send_complete;
    void* callback_context;
} PENDING_TRANSMISSION;


#define MAX_VALID_PORT 0xffff

// The TLSIO_RECEIVE_BUFFER_SIZE has very little effect on performance, and is kept small
// to minimize memory consumption.
#define TLSIO_RECEIVE_BUFFER_SIZE 64


typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_CLOSED,
	TLSIO_STATE_IN_HANDSHAKE,
    TLSIO_STATE_OPENING_WAITING_DNS,
    TLSIO_STATE_OPENING_WAITING_SOCKET,
    TLSIO_STATE_OPENING_WAITING_SSL,
    TLSIO_STATE_OPEN,
    TLSIO_STATE_ERROR,
} TLSIO_STATE;

bool is_an_opening_state(TLSIO_STATE state)
{
    return state == TLSIO_STATE_OPENING_WAITING_DNS ||
        state == TLSIO_STATE_OPENING_WAITING_SOCKET ||
        state == TLSIO_STATE_OPENING_WAITING_SSL;
}

typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_OPEN_COMPLETE on_open_complete;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_error_context;
    void* on_open_complete_context;
    mbedtls_entropy_context    entropy;
    mbedtls_ctr_drbg_context   ctr_drbg;
    mbedtls_ssl_context        ssl;
    mbedtls_ssl_config         config;
    mbedtls_x509_crt           trusted_certificates_parsed;
    mbedtls_ssl_session        ssn;
    char*                      trusted_certificates;
    TLSIO_STATE tlsio_state;
    DNS_ASYNC_HANDLE dns;
    char* hostname;
    uint16_t port;
    SOCKET_ASYNC_HANDLE sock;
    SINGLYLINKEDLIST_HANDLE pending_transmission_list;
} TLS_IO_INSTANCE;

/* Codes_SRS_TLSIO_30_005: [ The phrase "enter TLSIO_STATE_EXT_ERROR" means the adapter shall call the on_io_error function and pass the on_io_error_context that was supplied in tlsio_open_async. ]*/
static void enter_tlsio_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
    }
}

/* Codes_SRS_TLSIO_30_005: [ When the adapter enters TLSIO_STATE_EXT_ERROR it shall call the  on_io_error function and pass the on_io_error_context that were supplied in  tlsio_open . ]*/
static void enter_open_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    enter_tlsio_error_state(tls_io_instance);
    // on_open_complete has already been checked for non-NULL
    tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_ERROR);
}

// Return true if a message was available to remove
static bool process_and_destroy_head_message(TLS_IO_INSTANCE* tls_io_instance, IO_SEND_RESULT send_result)
{
    bool result;
    LIST_ITEM_HANDLE head_pending_io;
    if (send_result == IO_SEND_ERROR)
    {
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        enter_tlsio_error_state(tls_io_instance);
    }
    head_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    if (head_pending_io != NULL)
    {
        PENDING_TRANSMISSION* head_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(head_pending_io);
        // on_send_complete is checked for NULL during PENDING_TRANSMISSION creation
        /* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
        head_message->on_send_complete(head_message->callback_context, send_result);

        free(head_message->bytes);
        free(head_message);
        if (singlylinkedlist_remove(tls_io_instance->pending_transmission_list, head_pending_io) != 0)
        {
            // This particular situation is a bizarre and unrecoverable internal error
            /* Codes_SRS_TLSIO_30_094: [ If the send process encounters an internal error or calls on_send_complete with IO_SEND_ERROR due to either failure or timeout, it shall also call on_io_error and pass in the associated on_io_error_context. ]*/
            enter_tlsio_error_state(tls_io_instance);
            LogError("Failed to remove message from list");
        }
        result = true;
    }
    else
    {
        result = false;
    }
    return result;
}


void tlsio_mbedtls_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io != NULL)
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        // mbedTLS cleanup...
        mbedtls_ssl_close_notify(&tls_io_instance->ssl);
        mbedtls_ssl_free(&tls_io_instance->ssl);
        mbedtls_ssl_config_free(&tls_io_instance->config);
        mbedtls_x509_crt_free(&tls_io_instance->trusted_certificates_parsed);
        mbedtls_ctr_drbg_free(&tls_io_instance->ctr_drbg);
        mbedtls_entropy_free(&tls_io_instance->entropy);

        /* Codes_SRS_TLSIO_30_021: [ The tlsio_destroy shall release all allocated resources and then release tlsio_handle. ]*/
        if (tls_io_instance->hostname != NULL)
        {
            free(tls_io_instance->hostname);
        }

        if (tls_io_instance->pending_transmission_list != NULL)
        {
            /* Pending messages were cleared in internal_close */
            singlylinkedlist_destroy(tls_io_instance->pending_transmission_list);
        }

        free(tls_io_instance);
    }
}

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
	dns_async_destroy(tls_io_instance->dns);
    tls_io_instance->dns = NULL;
	tlsio_mbedtls_destroy((CONCRETE_IO_HANDLE*)tls_io_instance);

    if (tls_io_instance->sock >= 0)
    {
        // The underlying socket API does not support waiting for close
        // to complete, so it isn't possible to do so.
        socket_async_destroy(tls_io_instance->sock);
        tls_io_instance->sock = -1;
    }

    while (process_and_destroy_head_message(tls_io_instance, IO_SEND_CANCELLED));
    // singlylinkedlist_destroy gets called in the main destroy

    tls_io_instance->on_bytes_received = NULL;
    tls_io_instance->on_io_error = NULL;
    tls_io_instance->on_bytes_received_context = NULL;
    tls_io_instance->on_io_error_context = NULL;
    tls_io_instance->tlsio_state = TLSIO_STATE_CLOSED;
    tls_io_instance->on_open_complete = NULL;
    tls_io_instance->on_open_complete_context = NULL;
}








static int tlsio_entropy_poll(void *v, unsigned char *output, size_t len, size_t *olen)
{
    srand(time(NULL));
    char *c = (char*)malloc(len);
    memset(c, 0, len);
    for (uint16_t i = 0; i < len; i++) {
        c[i] = rand() % 256;
    }
    memmove(output, c, len);
    *olen = len;

    free(c);
    return(0);
}



static int on_io_recv(void *context, unsigned char *buf, size_t sz)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
    //unsigned char* new_socket_io_read_bytes;
    
    size_t received_count = 0;
    result = socket_async_receive(tls_io_instance->sock, buf, sz, &received_count);

    /*while (tls_io_instance->socket_io_read_byte_count == 0)
    {
        xio_dowork(tls_io_instance->socket_io);
        if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
        {
            break;
        }
    }

    result = tls_io_instance->socket_io_read_byte_count;
    if (result > sz)
    {
        result = sz;
    }

    if (result > 0)
    {
        (void)memcpy((void *)buf, tls_io_instance->socket_io_read_bytes, result);
        (void)memmove(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_bytes + result, tls_io_instance->socket_io_read_byte_count - result);
        tls_io_instance->socket_io_read_byte_count -= result;
        if (tls_io_instance->socket_io_read_byte_count > 0)
        {
            new_socket_io_read_bytes = (unsigned char*)realloc(tls_io_instance->socket_io_read_bytes, tls_io_instance->socket_io_read_byte_count);
            if (new_socket_io_read_bytes != NULL)
            {
                tls_io_instance->socket_io_read_bytes = new_socket_io_read_bytes;
            }
        }
        else
        {
            free(tls_io_instance->socket_io_read_bytes);
            tls_io_instance->socket_io_read_bytes = NULL;
        }
    }


    if ((result == 0) && (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN))
    {
        result = MBEDTLS_ERR_SSL_WANT_READ;
    }*/

    if(!result) return received_count;
    return MBEDTLS_ERR_SSL_TIMEOUT;
}

static int on_io_send(void *context, const unsigned char *buf, size_t sz)
{
    int result;
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)context;
    
    size_t sent_count;
    result = socket_async_send(tls_io_instance->sock, buf, sz, &sent_count);

    /*if (xio_send(tls_io_instance->socket_io, buf, sz, tls_io_instance->on_send_complete, tls_io_instance->on_send_complete_callback_context) != 0)
    {
        tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
        indicate_error(tls_io_instance);
        result = 0;
    }
    else
    {
        result = sz;
    }*/

    return result;
}




static void mbedtls_init(void *instance, const char *host) {
    TLS_IO_INSTANCE *result = (TLS_IO_INSTANCE *)instance;
    char *pers = "azure_iot_client";

    // mbedTLS initialize...
    mbedtls_entropy_init(&result->entropy);
    mbedtls_ctr_drbg_init(&result->ctr_drbg);
    mbedtls_ssl_init(&result->ssl);
    mbedtls_ssl_session_init(&result->ssn);
    mbedtls_ssl_config_init(&result->config);
    mbedtls_x509_crt_init(&result->trusted_certificates_parsed);
    mbedtls_entropy_add_source(&result->entropy, tlsio_entropy_poll, NULL, 128, 0);
    mbedtls_ctr_drbg_seed(&result->ctr_drbg, mbedtls_entropy_func, &result->entropy, (const unsigned char *)pers, strlen(pers));
    mbedtls_ssl_config_defaults(&result->config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&result->config, mbedtls_ctr_drbg_random, &result->ctr_drbg);
    mbedtls_ssl_conf_authmode(&result->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_min_version(&result->config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);          // v1.2
    mbedtls_ssl_set_bio(&result->ssl, instance, on_io_send, on_io_recv, NULL);
    mbedtls_ssl_set_hostname(&result->ssl, host);
    mbedtls_ssl_set_session(&result->ssl, &result->ssn);

    mbedtls_ssl_setup(&result->ssl, &result->config);
}


static CONCRETE_IO_HANDLE tlsio_mbedtls_create(void* io_create_parameters)
{
    TLSIO_CONFIG* tls_io_config = io_create_parameters;
    TLS_IO_INSTANCE* result;

    if (tls_io_config == NULL)
    {
        LogError("NULL tls_io_config");
        result = NULL;
    }
    else
    {
        result = malloc(sizeof(TLS_IO_INSTANCE));
        if (result != NULL)
        {
				memset(result, 0, sizeof(TLS_IO_INSTANCE));
                result->on_bytes_received = NULL;
                result->on_bytes_received_context = NULL;


                result->on_io_error = NULL;
                result->on_io_error_context = NULL;

                result->trusted_certificates = NULL;
				
				
                    int ms_result;
                    
                    result->port = (uint16_t)tls_io_config->port;
                    result->tlsio_state = TLSIO_STATE_CLOSED;
                    result->sock = SOCKET_ASYNC_INVALID_SOCKET;
                    result->hostname = NULL;
                    result->dns = NULL;
                    result->pending_transmission_list = NULL;
                    /* Codes_SRS_TLSIO_30_016: [ tlsio_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
                    ms_result = mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
                    if (ms_result != 0)
                    {
                        /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                        LogError("malloc failed");
                        tlsio_mbedtls_destroy(result);
                        result = NULL;
                    }
                    else
                    {
                        // Create the message queue
                        result->pending_transmission_list = singlylinkedlist_create();
                        if (result->pending_transmission_list == NULL)
                        {
                            /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
                            LogError("Failed singlylinkedlist_create");
                            tlsio_mbedtls_destroy(result);
                            result = NULL;
                        }
                    }

                    // mbeTLS initialize
                    mbedtls_init((void *)result, tls_io_config->hostname);
                    result->tlsio_state = TLSIO_STATE_CLOSED;
        }
    }

    return result;
}



static int tlsio_mbedtls_open_async(CONCRETE_IO_HANDLE tls_io,
    ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
    ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
    ON_IO_ERROR on_io_error, void* on_io_error_context)
{

    int result;
    if (on_io_open_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
        LogError("Required parameter on_io_open_complete is NULL");
        result = __FAILURE__;
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_030: [ If the tlsio_handle parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL tlsio");
        }
        else
        {
            if (on_bytes_received == NULL)
            {
                /* Codes_SRS_TLSIO_30_032: [ If the on_bytes_received parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                LogError("Required parameter on_bytes_received is NULL");
                result = __FAILURE__;
            }
            else
            {
                if (on_io_error == NULL)
                {
                    /* Codes_SRS_TLSIO_30_033: [ If the on_io_error parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
                    LogError("Required parameter on_io_error is NULL");
                    result = __FAILURE__;
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

                    if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
                    {
                        /* Codes_SRS_TLSIO_30_037: [ If the adapter is in any state other than TLSIO_STATE_EXT_CLOSED when tlsio_open  is called, it shall log an error, and return FAILURE. ]*/
                        LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_CLOSED.");
                        result = __FAILURE__;
                    }
                    else
                    {
                        tls_io_instance->dns = dns_async_create(tls_io_instance->hostname, NULL);
                        if (tls_io_instance->dns == NULL)
                        {
                            /* Codes_SRS_TLSIO_30_038: [ If tlsio_open fails to enter TLSIO_STATE_EX_OPENING it shall return FAILURE. ]*/
                            LogError("dns_async_create failed");
                            result = __FAILURE__;
                        }
                        else
                        {
                            /* Codes_SRS_TLSIO_30_034: [ The tlsio_open shall store the provided on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context, on_io_open_complete, and on_io_open_complete_context parameters for later use as specified and tested per other line entries in this document. ]*/
                            tls_io_instance->on_bytes_received = on_bytes_received;
                            tls_io_instance->on_bytes_received_context = on_bytes_received_context;

                            tls_io_instance->on_io_error = on_io_error;
                            tls_io_instance->on_io_error_context = on_io_error_context;

                            tls_io_instance->on_open_complete = on_io_open_complete;
                            tls_io_instance->on_open_complete_context = on_io_open_complete_context;

                            /* Codes_SRS_TLSIO_30_035: [ On tlsio_open success the adapter shall enter TLSIO_STATE_EX_OPENING and return 0. ]*/
                            // All the real work happens in dowork
                            tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_DNS;
                            result = 0;
                        }
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_039: [ On failure, tlsio_open_async shall not call on_io_open_complete. ]*/
    }

    return result;
}

// This implementation does not have asynchronous close, but uses the _async name for consistencty with the spec
static int tlsio_mbedtls_close_async(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;

    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_050: [ If the tlsio_handle parameter is NULL, tlsio_openssl_close_async shall log an error and return FAILURE. ]*/
        LogError("NULL tlsio");
        result = __FAILURE__;
    }
    else
    {
        if (on_io_close_complete == NULL)
        {
            /* Codes_SRS_TLSIO_30_055: [ If the on_io_close_complete parameter is NULL, tlsio_openssl_close_async shall log an error and return FAILURE. ]*/
            LogError("NULL on_io_close_complete");
            result = __FAILURE__;
        }
        else
        {
            TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

            if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN &&
                tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
            {
                /* Codes_SRS_TLSIO_30_053: [ If the adapter is in any state other than TLSIO_STATE_EXT_OPEN or TLSIO_STATE_EXT_ERROR then tlsio_close_async shall log that tlsio_close_async has been called and then continue normally. ]*/
                // LogInfo rather than LogError because this is an unusual but not erroneous situation
                LogInfo("tlsio_openssl_close has been called when in neither TLSIO_STATE_OPEN nor TLSIO_STATE_ERROR.");
            }

            if (is_an_opening_state(tls_io_instance->tlsio_state))
            {
                /* Codes_SRS_TLSIO_30_057: [ On success, if the adapter is in TLSIO_STATE_EXT_OPENING, it shall call on_io_open_complete with the on_io_open_complete_context supplied in tlsio_open_async and IO_OPEN_CANCELLED. This callback shall be made before changing the internal state of the adapter. ]*/
                tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_CANCELLED);
            }
            // This adapter does not support asynchronous closing
            /* Codes_SRS_TLSIO_30_056: [ On success the adapter shall enter TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EX_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/
            /* Codes_SRS_TLSIO_30_052: [ On success tlsio_close shall return 0. ]*/
            internal_close(tls_io_instance);
            on_io_close_complete(callback_context);
            result = 0;
        }
    }
    /* Codes_SRS_TLSIO_30_054: [ On failure, the adapter shall not call on_io_close_complete. ]*/

    return result;
}

static int tlsio_mbedtls_send_async(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (on_send_complete == NULL)
    {
        /* Codes_SRS_TLSIO_30_062: [ If the on_send_complete is NULL, tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
        result = __FAILURE__;
        LogError("NULL on_send_complete");
    }
    else
    {
        if (tls_io == NULL)
        {
            /* Codes_SRS_TLSIO_30_060: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
            result = __FAILURE__;
            LogError("NULL tlsio");
        }
        else
        {
            if (buffer == NULL)
            {
                /* Codes_SRS_TLSIO_30_061: [ If the buffer is NULL, tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
                result = __FAILURE__;
                LogError("NULL buffer");
            }
            else
            {
                if (size == 0)
                {
                    /* Codes_SRS_TLSIO_30_067: [ If the  size  is 0,  tlsio_send  shall log the error and return FAILURE. ]*/
                    result = __FAILURE__;
                    LogError("0 size");
                }
                else
                {
                    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
                    if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
                    {
                        /* Codes_SRS_TLSIO_30_065: [ If tlsio_openssl_compact_open has not been called or the opening process has not been completed, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                        result = __FAILURE__;
                        LogError("tlsio_openssl_send_async without a prior successful open");
                    }
                    else
                    {
                        PENDING_TRANSMISSION* pending_transmission = (PENDING_TRANSMISSION*)malloc(sizeof(PENDING_TRANSMISSION));
                        if (pending_transmission == NULL)
                        {
                            /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                            result = __FAILURE__;
                            LogError("malloc failed");
                        }
                        else
                        {
                            /* Codes_SRS_TLSIO_30_063: [ The tlsio_openssl_compact_send shall enqueue for transmission the on_send_complete, the callback_context, the size, and the contents of buffer. ]*/
                            pending_transmission->bytes = (unsigned char*)malloc(size);

                            if (pending_transmission->bytes == NULL)
                            {
                                /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                                LogError("malloc failed");
                                free(pending_transmission);
                                result = __FAILURE__;
                            }
                            else
                            {
                                pending_transmission->size = size;
                                pending_transmission->unsent_size = size;
                                pending_transmission->on_send_complete = on_send_complete;
                                pending_transmission->callback_context = callback_context;
                                (void)memcpy(pending_transmission->bytes, buffer, size);

                                if (singlylinkedlist_add(tls_io_instance->pending_transmission_list, pending_transmission) == NULL)
                                {
                                    /* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
                                    LogError("Unable to add socket to pending list.");
                                    free(pending_transmission->bytes);
                                    free(pending_transmission);
                                    result = __FAILURE__;
                                }
                                else
                                {
                                    /* Codes_SRS_TLSIO_30_063: [ On success,  tlsio_send  shall enqueue for transmission the  on_send_complete , the  callback_context , the  size , and the contents of  buffer  and then return 0. ]*/
                                    result = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* Codes_SRS_TLSIO_30_066: [ On failure, on_send_complete shall not be called. ]*/
    }
    return result;
}

static void dowork_read(TLS_IO_INSTANCE* tls_io_instance)
{
    if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
    {
		unsigned char buffer[64];
		int rcv_bytes = 1;

		while (rcv_bytes > 0)
		{
			rcv_bytes = mbedtls_ssl_read(&tls_io_instance->ssl, buffer, sizeof(buffer));
			if (rcv_bytes > 0)
			{
				if (tls_io_instance->on_bytes_received != NULL)
				{
					tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
				}
			}
		}
    }
}


static int create_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
    
    return 0;
    
    /*int result;
    int ret;

    tls_io_instance->ssl_context = SSL_CTX_new(TLSv1_2_client_method());
    if (tls_io_instance->ssl_context == NULL)
    {
        result = __FAILURE__;
        LogError("create new SSL CTX failed");
    }

    return result;*/
}

static void dowork_send(TLS_IO_INSTANCE* tls_io_instance)
{
    LIST_ITEM_HANDLE first_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
    if (first_pending_io != NULL)
    {
        PENDING_TRANSMISSION* pending_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(first_pending_io);
        uint8_t* buffer = ((uint8_t*)pending_message->bytes) +
            pending_message->size - pending_message->unsent_size;

        int write_result = mbedtls_ssl_write(&tls_io_instance->ssl, buffer, pending_message->unsent_size);
        if (write_result > 0)
        {
            pending_message->unsent_size -= write_result;
            if (pending_message->unsent_size == 0)
            {
                /* Codes_SRS_TLSIO_30_091: [ If tlsio_openssl_compact_dowork is able to send all the bytes in an enqueued message, it shall call the messages's on_send_complete along with its associated callback_context and IO_SEND_OK. ]*/
                // The whole message has been sent successfully
                process_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
            }
            else
            {
                /* Codes_SRS_TLSIO_30_093: [ If the TLS connection was not able to send an entire enqueued message at once, subsequent calls to tlsio_dowork shall continue to send the remaining bytes. ]*/
                // Repeat the send on the next pass with the rest of the message
                // This empty else compiles to nothing but helps readability
            }
        }
        else
        {
            // SSL_write returned non-success. It may just be busy, or it may be broken.

        }
    }
    else
    {
        /* Codes_SRS_TLSIO_30_096: [ If there are no enqueued messages available, tlsio_openssl_compact_dowork shall do nothing. ]*/
    }
}

static void dowork_poll_dns(TLS_IO_INSTANCE* tls_io_instance)
{
    bool dns_is_complete = dns_async_is_lookup_complete(tls_io_instance->dns);

    if (dns_is_complete)
    {
        uint32_t host_ipV4_address = dns_async_get_ipv4(tls_io_instance->dns);
        dns_async_destroy(tls_io_instance->dns);
        tls_io_instance->dns = NULL;
        if (host_ipV4_address == 0)
        {
            // Transition to TSLIO_STATE_ERROR
            /* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
            // The DNS failure has already been logged
            enter_open_error_state(tls_io_instance);
        }
        else
        {
            SOCKET_ASYNC_HANDLE sock = socket_async_create(host_ipV4_address, tls_io_instance->port, false, NULL);
            if (sock < 0)
            {
                // This is a communication interruption rather than a program bug
                /* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
                LogInfo("Could not open the socket");
                enter_open_error_state(tls_io_instance);
            }
            else
            {
                // The socket has been created successfully, so now wait for it to
                // finish the TCP handshake.
                tls_io_instance->sock = sock;
                tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SOCKET;
            }
        }
    }
}

static void dowork_poll_socket(TLS_IO_INSTANCE* tls_io_instance)
{
    bool is_complete;
    int result = socket_async_is_create_complete(tls_io_instance->sock, &is_complete);
    if (result != 0)
    {
        // Transition to TSLIO_STATE_ERROR
        LogInfo("socket_async_is_create_complete failure");
        enter_open_error_state(tls_io_instance);
    }
    else
    {
        if (is_complete)
        {
            // Attempt to transition to TLSIO_STATE_OPENING_WAITING_SSL
            int create_ssl_result = create_ssl(tls_io_instance);
            if (create_ssl_result != 0)
            {
                // Transition to TSLIO_STATE_ERROR
                // create_ssl already did error logging
                enter_open_error_state(tls_io_instance);
            }
            else
            {
                tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SSL;
            }
        }
    }
}

static void dowork_poll_open_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
	
        tls_io_instance->tlsio_state = TLSIO_STATE_IN_HANDSHAKE;
        int result;
        do {
            result = mbedtls_ssl_handshake(&tls_io_instance->ssl);
        } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (result == 0)
        {
            tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
            tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_OK);
        }
        else
        {

        }

}

static void tlsio_mbedtls_dowork(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io == NULL)
    {
        /* Codes_SRS_TLSIO_30_070: [ If the tlsio_handle parameter is NULL, tlsio_dowork shall do nothing except log an error. ]*/
        LogError("NULL tlsio");
    }
    else
    {
        TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;

        // This switch statement handles all of the state transitions during the opening process
        switch (tls_io_instance->tlsio_state)
        {
        case TLSIO_STATE_CLOSED:
            /* Codes_SRS_TLSIO_30_075: [ If the adapter is in TLSIO_STATE_EXT_CLOSED then  tlsio_dowork  shall do nothing. ]*/
            // Waiting to be opened, nothing to do
            break;
        case TLSIO_STATE_OPENING_WAITING_DNS:
            //LogInfo("dowork_poll_dns");
            dowork_poll_dns(tls_io_instance);
            break;
        case TLSIO_STATE_OPENING_WAITING_SOCKET:
            //LogInfo("dowork_poll_socket");
            dowork_poll_socket(tls_io_instance);
            break;
        case TLSIO_STATE_OPENING_WAITING_SSL:
            //LogInfo("dowork_poll_ssl");
            dowork_poll_open_ssl(tls_io_instance);
            break;
        case TLSIO_STATE_OPEN:
            dowork_read(tls_io_instance);
            dowork_send(tls_io_instance);
            break;
        case TLSIO_STATE_ERROR:
            /* Codes_SRS_TLSIO_30_071: [ If the adapter is in TLSIO_STATE_EXT_ERROR then tlsio_dowork shall do nothing. ]*/
            // There's nothing valid to do here but wait to be retried
            break;
        default:
            LogError("Unexpected internal tlsio state");
            break;
        }
    }
}

static int tlsio_mbedtls_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_120: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    int result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = __FAILURE__;
    }
    else
    {
        /* Codes_SRS_TLSIO_30_121: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
        if (optionName == NULL)
        {
            LogError("Required optionName parameter is NULL");
            result = __FAILURE__;
        }
        else
        {
            /* Codes_SRS_TLSIO_30_122: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
            if (value == NULL)
            {
                LogError("Required value parameter is NULL");
                result = __FAILURE__;
            }
            else
            {
                /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_520 [ The tlsio_setoption shall do nothing and return 0. ]*/
                result = 0;
            }
        }
    }
    return result;
}

/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_560: [ The  tlsio_retrieveoptions  shall do nothing and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_mbedtls_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
    TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
    /* Codes_SRS_TLSIO_30_160: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
    OPTIONHANDLER_HANDLE result;
    if (tls_io_instance == NULL)
    {
        LogError("NULL tlsio");
        result = NULL;
    }
    else
    {
        result = NULL;
    }
    return result;
}

/* Codes_SRS_TLSIO_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
static const IO_INTERFACE_DESCRIPTION tlsio_mbedtls_interface_description =
{
    tlsio_mbedtls_retrieveoptions,
    tlsio_mbedtls_create,
    tlsio_mbedtls_destroy,
    tlsio_mbedtls_open_async,
    tlsio_mbedtls_close_async,
    tlsio_mbedtls_send_async,
    tlsio_mbedtls_dowork,
    tlsio_mbedtls_setoption
};


const IO_INTERFACE_DESCRIPTION* tlsio_mbedtls_get_interface_description(void)
{
    return &tlsio_mbedtls_interface_description;
}