#ifndef NFL_BLOCK_H_
#define NFL_BLOCK_H_

#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include <thread.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Type to represent a block of key pair
 * @details This structure does not own the memory pointed by 
 *          @p pub and @p pvt. The user must make sure the 
 *          memory blocks pointed by are still valid as long as 
 *          this structure is in use.
 */
typedef struct nfl_key_pair {
    const uint8_t* pub;     
    const uint8_t* pvt;          
} nfl_key_pair_t;

/**
 * @brief   Type to represent a bootstrap tuple
 * @details m_cert represent the allocated cert in bootstrapping
 *          home_prefix represent the name TLV encoded home prefix
 */
typedef struct nfl_bootstrap_tuple {
    ndn_block_t m_cert;     
    ndn_block_t anchor_cert;
    ndn_block_t home_prefix;        
} nfl_bootstrap_tuple_t;

/**
 * @brief   Type to represent a discovery tuple
 * @details This structure does not own the memory pointed by @p identity 
 *          and @p service. The user must make sure the memory blocks pointed 
 *          are still valid as long as this structure is in use.
 */
typedef struct nfl_discovery_tuple {
    ndn_block_t* identity;     
    ndn_block_t* service;       
} nfl_discovery_tuple_t;

/**
 * @brief   Type to represent a access tuple
 *          @p ace represent ECDSA key pair used in access control
 *          @p opt represent optional parameter in block, can be NULL 
 *          no optional parameter
 * @details This structure does not own the memory pointed by @p ace 
 *          and @p opt. The user must make sure the memory blocks 
 *          pointed are still valid as long as this structure is in use.
 */
typedef struct nfl_access_tuple {
    nfl_key_pair_t* ace;
    ndn_block_t* opt;
} nfl_access_tuple_t;

#ifdef __cplusplus
}
#endif

#endif /* NFL_BLOCK_H_ */
/** @} */