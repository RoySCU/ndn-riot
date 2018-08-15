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

int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32])
{
    msg_t msg, reply;
    msg.type = NFL_START_BOOTSTRAP;
    nfl_key_pair_t key;
    key.pub = BKpub;
    key.pvt = BKpvt;
    msg.content.ptr = &key;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

int nfl_extract_bootstrap_tuple(nfl_bootstrap_tuple_t* tuple)
{
    (void)tuple;//initialize
    msg_t msg, reply;
    msg.type = NFL_EXTRACT_BOOTSTRAP_TUPLE;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    tuple = reply.content.ptr;
    return true;
}

int nfl_start_discovery(void)
{
    msg_t msg, reply;
    msg.type = NFL_START_DISCOVERY;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

int nfl_set_discovery_prefix(const char* ptr)
{
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

int nfl_start_discovery_query(nfl_discovery_tuple_t* tuple)
{
    msg_t msg, reply;
    msg.type = NFL_START_DISCOVERY_QUERY;
    msg.content.ptr = tuple;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return true;
}

nfl_identity_entry_t* nfl_extract_discovery_tuple(void)
{
    msg_t msg, reply;
    msg.type = NFL_EXTRACT_DISCOVERY_TUPLE;
    msg.content.ptr = NULL;
    msg_send_receive(&msg, &reply, nfl_pid); 

    return reply.content.ptr;
}
