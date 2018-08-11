#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include "app.h"
#include "ndn.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "nfl-constant.h"
#include "encoding/data.h"
#include "msg-type.h"
#include "crypto/ciphers.h"
#include "uECC.h"
#include <string.h>
#include "nfl-block.h"
#include "nfl-app.h"
#include "discovery.h"

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
    uECC_HashContext uECC;
    sha256_context_t ctx;
} uECC_SHA256_HashContext;
static void _init_sha256(const uECC_HashContext *base)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_init(&context->ctx);
}

static void _update_sha256(const uECC_HashContext *base,
                           const uint8_t *message,
                           unsigned message_size)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void _finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}
#endif


#define DPRINT(...) printf(__VA_ARGS__)

static ndn_app_t* handle = NULL;

static ndn_block_t home_prefix;
static ndn_block_t served_prefixes;

static uint8_t com_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

/*
static uint8_t com_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key


static uint8_t ecc_key_pri[] = {
    0x00, 0x79, 0xD8, 0x8A, 0x5E, 0x4A, 0xF3, 0x2D,
    0x36, 0x03, 0x89, 0xC7, 0x92, 0x3B, 0x2E, 0x50, 
    0x7C, 0xF7, 0x6E, 0x60, 0xB0, 0xAF, 0x26, 0xE4,
    0x42, 0x9D, 0xC8, 0xCE, 0xF0, 0xDE, 0x75, 0xB3 
};

static uint8_t ecc_key_pub[] = {
    0xB2, 0xFC, 0x62, 0x14, 0x78, 0xDC, 0x10, 0xEA, 
    0x61, 0x42, 0xB9, 0x34, 0x67, 0xE6, 0xDD, 0xE3,
    0x3D, 0x35, 0xAA, 0x5B, 0xA4, 0x24, 0x6C, 0xD4, 
    0xB4, 0xED, 0xD8, 0xA4, 0x59, 0xA7, 0x32, 0x12,
    0x57, 0x37, 0x90, 0x5D, 0xED, 0x37, 0xC8, 0xE8,
    0x6A, 0x81, 0xE5, 0x8F, 0xBE, 0x6B, 0xD3, 0x27,
    0x20, 0xBB, 0x16, 0x2A, 0xD3, 0x2F, 0xB5, 0x11, 
    0x1B, 0xD1, 0xAF, 0x76, 0xDB, 0xAD, 0xB8, 0xCE
}; // this is secp160r1 key*/


//segment for signature and buffer_signature to write, returning the pointer to the buffer
//this function will automatically skip the NAME header, so just pass the whole NAME TLV 
static int ndn_make_signature(uint8_t pri_key[32], ndn_block_t* seg, uint8_t* buf_sig)
{
    uint32_t num;
    buf_sig[0] = NDN_TLV_SIGNATURE_VALUE;
    ndn_block_put_var_number(64, buf_sig + 1, 66 -1);
    int gl = ndn_block_get_var_number(seg->buf + 1, seg->len - 1, &num);
    uint8_t h[32] = {0}; 

    sha256(seg->buf + 1 + gl, seg->len - 1 - gl, h);
    uECC_Curve curve = uECC_secp160r1();

#ifndef FEATURE_PERIPH_HWRNG
    // allocate memory on heap to avoid stack overflow
    uint8_t *tmp = (uint8_t*)malloc(32 + 32 + 64);
    if (tmp == NULL) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }

    uECC_SHA256_HashContext *ctx = (uECC_SHA256_HashContext*)
                malloc(sizeof(uECC_SHA256_HashContext));
    if (ctx == NULL) {
        free(tmp);
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
       
    ctx->uECC.init_hash = &_init_sha256;
    ctx->uECC.update_hash = &_update_sha256;
    ctx->uECC.finish_hash = &_finish_sha256;
    ctx->uECC.block_size = 64;
    ctx->uECC.result_size = 32;
    ctx->uECC.tmp = tmp;
    int res = uECC_sign_deterministic(pri_key, h, sizeof(h), &ctx->uECC,
                                              buf_sig + 1 + gl, curve); 
    free(ctx);
    free(tmp);
    if (res == 0) {
        DPRINT("nfl-bootstrap: Error during signing interest\n");
        return -1;
    }
#else
    res = uECC_sign(pri_key, h, sizeof(h), buf_sig + 1 + gl, curve);
    if (res == 0) {
        return -1;
    }  
    return 0; //success
#endif
    return 0; //success
}

static int query_timeout(ndn_block_t* interest);

static int on_query_response(ndn_block_t* interest, ndn_block_t* data)
{
    /*
        Controller: Data -> 
        /<home prefix>/service/<CK signature>/<version>
        All served prefixes about <service name> in Name TLV
        (e.g, /ucla/temperature/397/desk01) 
        CK signature
    */
    (void)interest;
    ndn_block_t name;

    int r = ndn_data_get_name(data, &name); 
    assert(r == 0);
    DPRINT("query response received, name=");
    ndn_name_print(&name);
    putchar('\n');

    r = ndn_data_verify_signature(data, com_key_pri, sizeof(com_key_pri)); 
    if (r != 0)
        DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): fail to verify query response\n",
               handle->id);
    else{ 
        DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): query response valid\n",
               handle->id);

    /* install the served prefixes */
    ndn_block_t content;
    r = ndn_data_get_content(data, &content);
    assert(r == 0);        
    //skip the content header and install served prefixes
    served_prefixes.buf = content.buf + 2;
    served_prefixes.len = content.len - 2;
   
    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): served prefixes block installed, length = %d\n",
               handle->id,  served_prefixes.len);
    }
    return NDN_APP_STOP;  // block forever...
}

static int ndn_app_express_discovery_query(void) 
{
  // Device: Interest->/<home prefix>/service/<CK signature>


    /* append the "service" */
    const char* uri_query = "/service"; 
    ndn_shared_block_t* sn_query = ndn_name_from_uri(uri_query, strlen(uri_query));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* sn1_query = ndn_name_append(&home_prefix,
                                 (&sn_query->block)->buf + 4, (&sn_query->block)->len - 4);

    ndn_shared_block_release(sn_query);

    //now we have signinfo but carrying no keylocator
    // Write signature info header 
    uint8_t* buf_sinfo = (uint8_t*)malloc(5); 
    buf_sinfo[0] = NDN_TLV_SIGNATURE_INFO;
    buf_sinfo[1] = 3;

    // Write signature type (true signatureinfo content)
    buf_sinfo[2] = NDN_TLV_SIGNATURE_TYPE;
    buf_sinfo[3] = 1;
    buf_sinfo[4] = NDN_SIG_TYPE_ECDSA_SHA256;

    //append the signatureinfo
    ndn_shared_block_t* sn2_query = ndn_name_append(&sn1_query->block, buf_sinfo, 5); 
    ndn_shared_block_release(sn1_query);

    /* append the signature by CK */
    uint8_t buf_ck[66]; //64 bytes reserved from the value, 2 bytes for header 
    ndn_make_signature(com_key_pri, &sn2_query->block, buf_ck);
    ndn_shared_block_t* sn3_query = ndn_name_append(&sn2_query->block, buf_ck, 66);   
    ndn_shared_block_release(sn2_query);

    DPRINT("nfl-discovery: express Service Discovery Query, name=");
    ndn_name_print(&sn3_query->block);
    putchar('\n');

    uint32_t lifetime = 3000;  // 1 sec
    int r = ndn_app_express_interest(handle, &sn3_query->block, NULL, lifetime,
                                     on_query_response, 
                                     query_timeout); 
    ndn_shared_block_release(sn3_query);
    if (r != 0) {
        DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): failed to express query\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    return NDN_APP_CONTINUE;
}

static int on_upload_request(ndn_block_t* interest)
{
    /* 
        Controller: Interest->/<home prefix>/<valid host name>/service/<CK signature>
    */
    ndn_block_t req;
    if (ndn_interest_get_name(interest, &req) != 0) {
        DPRINT("Device (pid=%" PRIkernel_pid "): cannot get name from Service Upload Request"
               "\n", handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Device (pid=%" PRIkernel_pid "): Serive Upload Request received, name=",
           handle->id);
    ndn_name_print(&req);
    putchar('\n');

    ndn_shared_block_t* upload_name = ndn_name_append_uint8(&req, 3);
    if (upload_name == NULL) {
        DPRINT("Device (pid=%" PRIkernel_pid "): cannot append Version component to "
               "name\n", handle->id);
        return NDN_APP_ERROR;
    }

    //set the metainfo
    ndn_metainfo_t meta = { NDN_CONTENT_TYPE_BLOB, -1 };
    

    //TODO: to extract from NFL the list of served prefixes
    const char* served_prefix0 = "/irl/printer/394/setOn";
    const char* served_prefix1 = "/irl/temperture/397/read";
    const char* served_prefix2 = "/irl/light/374/setDim";
    ndn_shared_block_t* service[3];
    service[0] = ndn_name_from_uri(served_prefix0, strlen(served_prefix0));
    service[1] = ndn_name_from_uri(served_prefix1, strlen(served_prefix1));
    service[2] = ndn_name_from_uri(served_prefix2, strlen(served_prefix2));

    //prepare the uploaded content
    ndn_block_t bigbuffer;
    bigbuffer.buf = (uint8_t*)malloc(service[0]->block.len + 
                                     service[1]->block.len + 
                                     service[2]->block.len);
    bigbuffer.len = service[0]->block.len + 
                                     service[1]->block.len + 
                                     service[2]->block.len;

    DPRINT(" length of uploaded content length : %d\n", bigbuffer.len);
    
    //payload
    memcpy(&bigbuffer, service[0]->block.buf, service[0]->block.len);
    memcpy(&bigbuffer + service[0]->block.len, service[1]->block.buf,
                                               service[1]->block.len);
    memcpy(&bigbuffer + service[0]->block.len + service[1]->block.len,
                        service[2]->block.buf, service[2]->block.len);
    //make the packet
    ndn_shared_block_t* uploaded_packet =
        ndn_data_create(&upload_name->block, &meta, &bigbuffer,
                        NDN_SIG_TYPE_ECDSA_SHA256, NULL,
                        com_key_pri, sizeof(com_key_pri));
    if (uploaded_packet == NULL) {
        DPRINT("Device (pid=%" PRIkernel_pid "): cannot create uploaded packet\n",
               handle->id);
        ndn_shared_block_release(upload_name);
        return NDN_APP_ERROR;
    }

    DPRINT("Device (pid=%" PRIkernel_pid "): send Uploaded Packet to NDN thread, name=",
           handle->id);
    ndn_name_print(&upload_name->block);
    putchar('\n');
    ndn_shared_block_release(upload_name);

    // pass ownership of "sd" to the API
    if (ndn_app_put_data(handle, uploaded_packet) != 0) {
        DPRINT("Device (pid=%" PRIkernel_pid "): cannot put Uploaded Packet\n",
               handle->id);
        return NDN_APP_ERROR;
    }

    DPRINT("Device (pid=%" PRIkernel_pid "): return to the app\n", handle->id);
    free(uploaded_packet);
    return NDN_APP_STOP;
}

static int query_timeout(ndn_block_t* interest)
{
    (void)interest;
    DPRINT("Service Discovery Query Timeout\n");
    return NDN_APP_CONTINUE; 
}

void *ndn_discovery(nfl_bootstrap_tuple_t* bootstrapTuple)
{
    if(bootstrapTuple == NULL){
        DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): no bootstrapTuple available\n",
               thread_getpid());
    }

    //install home prefix from bootstrapTuple
    home_prefix.buf = bootstrapTuple->home_prefix->buf;
    home_prefix.len = bootstrapTuple->home_prefix->len;

    msg_t msg, reply;

    handle = ndn_app_create();
    if (handle == NULL) {
        DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): cannot create app handle\n",
               thread_getpid());
        return NULL;
    }

    /*
        Controller: Interest->/<home prefix>/<valid host name>/service/<CK signature>
    */
    ndn_block_t r;
    ndn_data_get_name(bootstrapTuple->m_cert, &r);

    const char* uri_req = "/service"; 
    ndn_shared_block_t* sn_req = ndn_name_from_uri(uri_req, strlen(uri_req));
    //move the pointer by 4 bytes: 2 bytes for name header, 2 bytes for component header
    ndn_shared_block_t* reg = ndn_name_append(&r,
                                 (&sn_req->block)->buf + 4, (&sn_req->block)->len - 4);

    if (ndn_app_register_prefix(handle, reg, on_upload_request) != 0) {
        DPRINT("Device (pid=%" PRIkernel_pid "): failed to register upload prefix\n",
               handle->id);
        ndn_app_destroy(handle);
        return NULL;
    }

    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): enter round trip 1\n",
           handle->id);
    ndn_app_run(handle);
    ndn_app_destroy(handle);

    handle = ndn_app_create();
    ndn_app_express_discovery_query();  /* round trip two */
    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): enter round trip 2\n",
           handle->id);
    ndn_app_run(handle);
    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): returned from trip 2\n",
           handle->id);

    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): into ipc loop\n", handle->id);

    while(1){
    msg_receive(&msg);
    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): ipc request got\n", handle->id);
    nfl_discovery_tuple_t tuple = { &served_prefixes, 3};
    reply.content.ptr = &tuple;
    msg_reply(&msg, &reply);
    DPRINT("nfl-discovery: (pid=%" PRIkernel_pid "): ipc loop quit\n", handle->id);
    break; 
    }

    ndn_app_destroy(handle);
    return NULL;
}