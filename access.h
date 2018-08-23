#ifndef NDN_ACCESS_H_
#define NDN_ACCESS_H_

#include "nfl-block.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACE_CONTROLLER 1
#define ACE_CONSUMER   2
#define ACE_PRODUCER   3
#define ACE_PRODUCER_GLOBAL 4
#define ACE_CONSUMER_GLOBAL 5
#define ACE_USER_DEFINED 6
#define ACE_PRODUCER_USER_DEFINED 7
#define ACE_CONSUMER_USER_DEFINED 8

void *nfl_access(void* bootstrapTuple);


#ifdef __cplusplus
}
#endif

#endif /* NDN_ACCESS_H_ */
/** @} */