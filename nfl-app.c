#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>
#include "nfl-block.h"
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
    DEBUG("NFL: bootstrap request processed from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);


    return true;
}

int nfl_extract_home_prefix(ndn_block_t* home_prefix)
{
    return true;
}

int nfl_extract_m_cert(ndn_block_t* m_Certificate)
{
    return true;
}

int nfl_extract_anchor_cert(ndn_block_t* anchor_cert)
{
    return true;
}
