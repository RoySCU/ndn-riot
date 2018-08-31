#include <inttypes.h>
#include <sys/types.h>
#include "encoding/block.h"
#include "nfl-constant.h"
#include "nfl-block.h"
#include "discovery.h"
#include "access.h"


#ifndef NFL_APP_H_
#define NFL_APP_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief  Sends an bootstrap request to nfl thread
 *
 * @param[in]  key pair struct
 *
 * @return Bootstrap Tuple ptr, if success.
 * @return NULL, if out of memory during sending.
 * @return NULL, if timeout
 */
nfl_bootstrap_tuple_t* nfl_start_bootstrap(nfl_key_pair_t* pair);

/**
 * @brief  Extract bootstrap request from nfl thread
 *
 * @return Bootstrap Tuple ptr, if success.
 * @return NULL, if haven't bootstrapped yet.
 */
nfl_bootstrap_tuple_t* nfl_extract_bootstrap_tuple(void);

/**
 * @brief  Sends a discovery start request to nfl thread.
 *         This function will collect available subprefixes 
 *         and aggregate them into serveral services. Call 
 *         this function before init() and set() will incur 
 *         errors.
 *
 * @return 0, if success.
 * @return -1, if error.
 */
int nfl_start_discovery(void);

/**
 * @brief  Sends a access producer side request to nfl 
 *         thread. This function use identity based 
 *         scheme. Call this funtion before init() will 
 *         incur errors.  
 *         Caller must make copy
 * 
 * @param[in]  Access tuple ptr
 * 
 * @return Producer Seed ptr, if success.
 * @return NULL, if timeout 
 * @return NULL, if error.
 */
uint8_t* nfl_start_access_producer(nfl_access_tuple_t* tuple);

/**
 * @brief  Sends a access consumer side request to nfl 
 *         thread. This function use identity based 
 *         scheme. Call this funtion before init() will 
 *         incur errors.   
 *         Caller must make copy
 * 
 * @param[in]  Access tuple ptr
 * 
 * @return Producer Seed ptr, if success.
 * @return NULL, if timeout 
 * @return NULL, if error.
 */
uint8_t* nfl_start_access_consumer(nfl_access_tuple_t* tuple);

/**
 * @brief  Sends a setting discovery subprefix request to 
 *         nfl thread. Call this funtion before init() 
 *         will incur errors. 
 *
 * @param[in] Subprefix ptr in (char*) 
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int nfl_set_discovery_prefix(void* ptr);

/**
 * @brief  Sends a discovery init request to nfl thread. 
 *         nfl will create a thread for discovery thread. 
 *         init process includes initializing the identity
 *         table and subprefix table.
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int nfl_init_discovery(void);

/**
 * @brief  Sends a access init request to nfl thread. 
 *         nfl will create a thread for access control 
 *         thread. 
 * 
 * @return 0, if success.
 * @return -1, if error.
 */
int nfl_init_access(void);

/**
 * @brief  Sends a discovery query request to nfl thread. 
 *         Call this funtion before init() will incur errors. 
 *         Caller must make copy
 * 
 * @param[in] Discovery tuple ptr 
 * 
 * @return Metadata ptr, if success.
 * @return NULL, if timeout.
 * @return NULL, if error.
 */
ndn_block_t* nfl_start_discovery_query(nfl_discovery_tuple_t* tuple);

/**
 * @brief  Sends a discovery list extract request to nfl 
 *         thread. Call this funtion before init() will 
 *         incur errors. identity table hold identities 
 *         collected from the start of service discovery.
 *         Call this funtion before init() will incur errors 
 *         nfl thread will hold the memory of identity table
 * 
 * @return identity table ptr, if success.
 * @return NULL, if error.
 */
nfl_identity_entry_t* nfl_extract_discovery_list(void);


#ifdef __cplusplus
}
#endif

#endif /* NFL_APP_H_ */
/** @} */
