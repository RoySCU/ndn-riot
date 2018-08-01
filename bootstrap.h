#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include "thread.h"
#include "random.h"
#include "xtimer.h"
#include <hashes/sha256.h>
#include <app.h>
#include <ndn.h>
#include <msg-type.h>
#include <crypto/ciphers.h>
#include <uECC.h>
#include <string.h>

static void *ndn_bootstrap(void *ptr);