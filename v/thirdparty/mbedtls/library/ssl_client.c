

#include "common.h"

#if defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) || defined(MBEDTLS_SSL_PROTO_TLS1_2)

#include "mbedtls/platform.h"

#include <string.h>

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif

#include "ssl_client.h"
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hostname_ext( mbedtls_ssl_context *ssl,
                                   unsigned char *buf,
                                   const unsigned char *end,
                                   size_t *olen )
{
    unsigned char *p = buf;
    size_t hostname_len;

    *olen = 0;

    if( ssl->hostname == NULL )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "client hello, adding server name extension: %s",
          ssl->hostname ) );

    hostname_len = strlen( ssl->hostname );

    MBEDTLS_SSL_CHK_BUF_PTR( p, end, hostname_len + 9 );

   
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SERVERNAME, p, 0 );
    p += 2;

    MBEDTLS_PUT_UINT16_BE( hostname_len + 5, p, 0 );
    p += 2;

    MBEDTLS_PUT_UINT16_BE( hostname_len + 3, p, 0 );
    p += 2;

    *p++ = MBEDTLS_BYTE_0( MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME );

    MBEDTLS_PUT_UINT16_BE( hostname_len, p, 0 );
    p += 2;

    memcpy( p, ssl->hostname, hostname_len );

    *olen = hostname_len + 9;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_set_hs_sent_ext_mask( ssl, MBEDTLS_TLS_EXT_SERVERNAME );
#endif
    return( 0 );
}
#endif

#if defined(MBEDTLS_SSL_ALPN)

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_alpn_ext( mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               const unsigned char *end,
                               size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    if( ssl->conf->alpn_list == NULL )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding alpn extension" ) );


   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_ALPN, p, 0 );
   
    p += 6;

   
    for( const char **cur = ssl->conf->alpn_list; *cur != NULL; cur++ )
    {
       
        size_t protocol_name_len = strlen( *cur );

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 + protocol_name_len );
        *p++ = (unsigned char)protocol_name_len;
        memcpy( p, *cur, protocol_name_len );
        p += protocol_name_len;
    }

    *out_len = p - buf;

   
    MBEDTLS_PUT_UINT16_BE( *out_len - 6, buf, 4 );

   
    MBEDTLS_PUT_UINT16_BE( *out_len - 4, buf, 2 );

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_set_hs_sent_ext_mask( ssl, MBEDTLS_TLS_EXT_ALPN );
#endif
    return( 0 );
}
#endif

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                           unsigned char *buf,
                                           const unsigned char *end,
                                           size_t *out_len )
{
    unsigned char *p = buf ;
    unsigned char *named_group_list;
    size_t named_group_list_len;    
    const uint16_t *group_list = mbedtls_ssl_get_groups( ssl );

    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    named_group_list = p;

    if( group_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for( ; *group_list != 0; group_list++ )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got supported group(%04x)", *group_list ) );

#if defined(MBEDTLS_ECP_C)
        if( ( mbedtls_ssl_conf_is_tls13_enabled( ssl->conf ) &&
              mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) ) ||
            ( mbedtls_ssl_conf_is_tls12_enabled( ssl->conf ) &&
              mbedtls_ssl_tls12_named_group_is_ecdhe( *group_list ) ) )
        {
            const mbedtls_ecp_curve_info *curve_info;
            curve_info = mbedtls_ecp_curve_info_from_tls_id( *group_list );
            if( curve_info == NULL )
                continue;
            MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
            MBEDTLS_PUT_UINT16_BE( *group_list, p, 0 );
            p += 2;
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup: %s ( %x )",
                                curve_info->name, *group_list ) );
        }
#endif
       

    }

   
    named_group_list_len = p - named_group_list;
    if( named_group_list_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No group available." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

   
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS, buf, 0 );
   
    MBEDTLS_PUT_UINT16_BE( named_group_list_len + 2, buf, 2 );
   
    MBEDTLS_PUT_UINT16_BE( named_group_list_len, buf, 4 );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Supported groups extension",
                           buf + 4, named_group_list_len + 2 );

    *out_len = p - buf;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_set_hs_sent_ext_mask(
        ssl, MBEDTLS_TLS_EXT_SUPPORTED_GROUPS );
#endif

    return( 0 );
}

#endif

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_client_hello_cipher_suites(
            mbedtls_ssl_context *ssl,
            unsigned char *buf,
            unsigned char *end,
            int *tls12_uses_ec,
            size_t *out_len )
{
    unsigned char *p = buf;
    const int *ciphersuite_list;
    unsigned char *cipher_suites;
    size_t cipher_suites_len;

    *tls12_uses_ec = 0;
    *out_len = 0;

   
    ciphersuite_list = ssl->conf->ciphersuite_list;

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p += 2;

   
    cipher_suites = p;
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        int cipher_suite = ciphersuite_list[i];
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );

        if( mbedtls_ssl_validate_ciphersuite( ssl, ciphersuite_info,
                                              ssl->handshake->min_tls_version,
                                              ssl->tls_version ) != 0 )
            continue;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
      defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) )
        *tls12_uses_ec |= mbedtls_ssl_ciphersuite_uses_ec( ciphersuite_info );
#endif

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %04x, %s",
                                    (unsigned int) cipher_suite,
                                    ciphersuite_info->name ) );

       
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( cipher_suite, p, 0 );
        p += 2;
    }

   
    int renegotiating = 0;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    renegotiating = ( ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE );
#endif
    if( !renegotiating )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding EMPTY_RENEGOTIATION_INFO_SCSV" ) );
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO, p, 0 );
        p += 2;
    }

   
    cipher_suites_len = p - cipher_suites;
    MBEDTLS_PUT_UINT16_BE( cipher_suites_len, buf, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3,
                           ( "client hello, got %" MBEDTLS_PRINTF_SIZET " cipher suites",
                             cipher_suites_len/2 ) );

   
    *out_len = p - buf;

    return( 0 );
}


MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_client_hello_body( mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        unsigned char *end,
                                        size_t *out_len,
                                        size_t *binders_len )
{
    int ret;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    unsigned char *p = buf;
    unsigned char *p_extensions_len;
    size_t output_len;              
    size_t extensions_len;          
    int tls12_uses_ec = 0;

    *out_len = 0;
    *binders_len = 0;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    unsigned char propose_tls12 =
        ( handshake->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_2 )
        &&
        ( MBEDTLS_SSL_VERSION_TLS1_2 <= ssl->tls_version );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    unsigned char propose_tls13 =
        ( handshake->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_3 )
        &&
        ( MBEDTLS_SSL_VERSION_TLS1_3 <= ssl->tls_version );
#endif

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    mbedtls_ssl_write_version( p, ssl->conf->transport,
                               MBEDTLS_SSL_VERSION_TLS1_2 );
    p += 2;

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    memcpy( p, handshake->randbytes, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, ssl->session_negotiate->id_len + 1 );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    memcpy( p, ssl->session_negotiate->id, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                              ssl->session_negotiate->id_len );

   
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned char cookie_len = 0;

        if( handshake->cookie != NULL )
        {
            MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, cookie",
                                   handshake->cookie,
                                   handshake->verify_cookie_len );
            cookie_len = handshake->verify_cookie_len;
        }

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, cookie_len + 1 );
        *p++ = cookie_len;
        if( cookie_len > 0 )
        {
            memcpy( p, handshake->cookie, cookie_len );
            p += cookie_len;
        }
    }
#endif

   
    ret = ssl_write_client_hello_cipher_suites( ssl, p, end,
                                                &tls12_uses_ec,
                                                &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    *p++ = 1;
    *p++ = MBEDTLS_SSL_COMPRESS_NULL;

   

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
   
    handshake->sent_extensions = MBEDTLS_SSL_EXT_MASK_NONE;
#endif

   
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p_extensions_len = p;
    p += 2;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
   
    ret = ssl_write_hostname_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif

#if defined(MBEDTLS_SSL_ALPN)
    ret = ssl_write_alpn_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if( propose_tls13 )
    {
        ret = mbedtls_ssl_tls13_write_client_hello_exts( ssl, p, end,
                                                         &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if(
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        ( propose_tls13 &&
          mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) ) ||
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        ( propose_tls12 && tls12_uses_ec ) ||
#endif
        0 )
    {
        ret = ssl_write_supported_groups_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    if(
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        ( propose_tls13 && mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) ) ||
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        propose_tls12 ||
#endif
       0 )
    {
        ret = mbedtls_ssl_write_sig_alg_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( propose_tls12 )
    {
        ret = mbedtls_ssl_tls12_write_client_hello_exts( ssl, p, end,
                                                         tls12_uses_ec,
                                                         &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
   
    if( propose_tls13 && mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) )
    {
        ret = mbedtls_ssl_tls13_write_identities_of_pre_shared_key_ext(
                  ssl, p, end, &output_len, binders_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif

   
    extensions_len = p - p_extensions_len - 2;

    if( extensions_len == 0 )
       p = p_extensions_len;
    else
    {
        MBEDTLS_PUT_UINT16_BE( extensions_len, p_extensions_len, 0 );
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %" \
                                    MBEDTLS_PRINTF_SIZET, extensions_len ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions",
                                  p_extensions_len, extensions_len );
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    MBEDTLS_SSL_PRINT_EXTS(
        3, MBEDTLS_SSL_HS_CLIENT_HELLO, handshake->sent_extensions );
#endif

    *out_len = p - buf;
    return( 0 );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_generate_random( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *randbytes = ssl->handshake->randbytes;
    size_t gmt_unix_time_len = 0;

   
    if( ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 )
    {
#if defined(MBEDTLS_HAVE_TIME)
        mbedtls_time_t gmt_unix_time = mbedtls_time( NULL );
        MBEDTLS_PUT_UINT32_BE( gmt_unix_time, randbytes, 0 );
        gmt_unix_time_len = 4;

        MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "client hello, current time: %" MBEDTLS_PRINTF_LONGLONG,
               (long long) gmt_unix_time ) );
#endif
    }

    ret = ssl->conf->f_rng( ssl->conf->p_rng,
                            randbytes + gmt_unix_time_len,
                            MBEDTLS_CLIENT_HELLO_RANDOM_LEN - gmt_unix_time_len );
    return( ret );
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_prepare_client_hello( mbedtls_ssl_context *ssl )
{
    int ret;
    size_t session_id_len;
    mbedtls_ssl_session *session_negotiate = ssl->session_negotiate;

    if( session_negotiate == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_HAVE_TIME)

   
    if( ssl->handshake->resume != 0 &&
        session_negotiate->tls_version == MBEDTLS_SSL_VERSION_TLS1_3 &&
        session_negotiate->ticket != NULL )
    {
        mbedtls_time_t now = mbedtls_time( NULL );
        uint64_t age = (uint64_t)( now - session_negotiate->ticket_received );
        if( session_negotiate->ticket_received > now ||
            age > session_negotiate->ticket_lifetime )
        {
           
            MBEDTLS_SSL_DEBUG_MSG(
                3, ( "Ticket expired, disable session resumption" ) );
            ssl->handshake->resume = 0;
        }
    }
#endif

    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

   
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE )
        ssl->handshake->min_tls_version = ssl->tls_version;
    else
#endif
    {
        if( ssl->handshake->resume )
        {
             ssl->tls_version = session_negotiate->tls_version;
             ssl->handshake->min_tls_version = ssl->tls_version;
        }
        else
        {
             ssl->tls_version = ssl->conf->max_tls_version;
             ssl->handshake->min_tls_version = ssl->conf->min_tls_version;
        }
    }

   
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ( ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM ) ||
        ( ssl->handshake->cookie == NULL ) )
#endif
    {
        ret = ssl_generate_random( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "Random bytes generation failed", ret );
            return( ret );
        }
    }

   
    session_id_len = session_negotiate->id_len;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 )
    {
        if( session_id_len < 16 || session_id_len > 32 ||
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE ||
#endif
            ssl->handshake->resume == 0 )
        {
            session_id_len = 0;
        }

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
   
        int renegotiating = 0;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE )
            renegotiating = 1;
#endif
        if( !renegotiating )
        {
            if( ( session_negotiate->ticket != NULL ) &&
                ( session_negotiate->ticket_len != 0 ) )
            {
                session_id_len = 32;
            }
        }
#endif
    }
#endif

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    if( ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3 )
    {
       
        session_id_len = 32;
    }
#endif

    if( session_id_len != session_negotiate->id_len )
    {
        session_negotiate->id_len = session_id_len;
        if( session_id_len > 0 )
        {
            ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                    session_negotiate->id,
                                    session_id_len );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "creating session id failed", ret );
                return( ret );
            }
        }
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3  &&
        ssl->handshake->resume )
    {
        int hostname_mismatch = ssl->hostname != NULL ||
                                session_negotiate->hostname != NULL;
        if( ssl->hostname != NULL && session_negotiate->hostname != NULL )
        {
            hostname_mismatch = strcmp(
                ssl->hostname, session_negotiate->hostname ) != 0;
        }

        if( hostname_mismatch )
        {
            MBEDTLS_SSL_DEBUG_MSG(
                1, ( "Hostname mismatch the session ticket, "
                     "disable session resumption." ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }
    }
    else
    {
        return mbedtls_ssl_session_set_hostname( session_negotiate,
                                                 ssl->hostname );
    }
#endif

    return( 0 );
}

int mbedtls_ssl_write_client_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len, binders_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_prepare_client_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg(
                                ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_write_client_hello_body( ssl, buf,
                                                       buf + buf_len,
                                                       &msg_len,
                                                       &binders_len ) );

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ssl->out_msglen = msg_len + 4;
        mbedtls_ssl_send_flight_completed( ssl );

       
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );

        if( ( ret = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", ret );
            return( ret );
        }

        if( ( ret = mbedtls_ssl_flight_transmit( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flight_transmit", ret );
            return( ret );
        }
    }
    else
#endif
    {

        mbedtls_ssl_add_hs_hdr_to_checksum( ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                            msg_len );
        ssl->handshake->update_checksum( ssl, buf, msg_len - binders_len );
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
        if( binders_len > 0 )
        {
            MBEDTLS_SSL_PROC_CHK(
                mbedtls_ssl_tls13_write_binders_of_pre_shared_key_ext(
                      ssl, buf + msg_len - binders_len, buf + msg_len ) );
            ssl->handshake->update_checksum( ssl, buf + msg_len - binders_len,
                                             binders_len );
        }
#endif

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg( ssl,
                                                                buf_len,
                                                                msg_len ) );
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    }


cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    return ret;
}

#endif
#endif
