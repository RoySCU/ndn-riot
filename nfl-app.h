#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include "nfl-constant.h"
/*
    this function is used for ndn-riot app send ipc message to NFL, to start bootstrap 
*/

/*static int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);*/



#ifndef NFL_APP_H_
#define NFL_APP_H_

#ifdef __cplusplus
extern "C" {
#endif

int nfl_start_bootstrap(uint8_t BKpub[64], uint8_t BKpvt[32]);

int nfl_extract_home_prefix(ndn_block_t* home_prefix);

int nfl_extract_m_cert(ndn_block_t* m_Certificate);

int nfl_extract_anchor_cert(ndn_block_t* anchor_cert);



#ifdef __cplusplus
}
#endif

#endif /* NFL_APP_H_ */
/** @} */
