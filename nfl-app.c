#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>
#include "ndn.h"
#include "nfl-core.h"
#include "nfl-app.h"
#include "nfl-constant.h"
#include <debug.h>
/*
    this function is used for ndn-riot app send ipc message to NFL, to start bootstrap 
*/

nfl_bootstrap_tuple_t* nfl_start_bootstrap(nfl_key_pair_t* pair)
{
    msg_t msg, reply;
    msg.type = NFL_START_BOOTSTRAP;
    msg.content.ptr = pair;
    msg_send_receive(&msg, &reply, nfl_pid); 
    
    //reply message would contain the bootstraptuple
    if(reply.content.ptr) {
        nfl_bootstrap_tuple_t* ptr = reply.content.ptr;
        return ptr;
    }

    return NULL;
}

nfl_bootstrap_tuple_t* nfl_extract_bootstrap_tuple(void)
{
    msg_t msg, reply;
    msg.type = NFL_EXTRACT_BOOTSTRAP_TUPLE;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    if(reply.content.ptr) {
        nfl_bootstrap_tuple_t* ptr = reply.content.ptr;
        return ptr;
    }

    return NULL;
}

int nfl_start_discovery(void)
{
    msg_t msg, reply;
    msg.type = NFL_START_DISCOVERY;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

uint8_t* nfl_start_access_producer(nfl_access_tuple_t* tuple)
{
    msg_t msg, reply;
    msg.type = NFL_START_ACCESS_PRODUCER;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, nfl_pid); 

    uint8_t* ret = reply.content.ptr;
    return ret;
}

uint8_t* nfl_start_access_consumer(nfl_access_tuple_t* tuple)
{
    msg_t msg, reply;
    msg.type = NFL_START_ACCESS_CONSUMER;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, nfl_pid); 

    uint8_t* ret = reply.content.ptr;
    return ret;
}

int nfl_start_discovery(void)
{
    msg_t msg, reply;
    msg.type = NFL_START_DISCOVERY;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

int nfl_set_discovery_prefix(void* ptr)
{  
    //ptr should indicate a uri
    msg_t msg, reply;
    msg.type = NFL_SET_DISCOVERY_PREFIX;
    msg.content.ptr = ptr;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

int nfl_init_discovery(void)
{
    msg_t msg, reply;
    msg.type = NFL_INIT_DISCOVERY;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

int nfl_init_access(void)
{
    msg_t msg, reply;
    msg.type = NFL_INIT_ACCESS;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

ndn_block_t* nfl_start_discovery_query(nfl_discovery_tuple_t* tuple)
{
    msg_t msg, reply;
    msg.type = NFL_START_DISCOVERY_QUERY;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, nfl_pid); 

    if(reply.content.ptr) {
        ndn_block_t* ptr = reply.content.ptr;
        return ptr;
    }

    return NULL;
}

nfl_identity_entry_t* nfl_extract_discovery_list(void)
{
    msg_t msg, reply;
    msg.type = NFL_EXTRACT_DISCOVERY_LIST;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return reply.content.ptr;
}
