#include "nfl-core.h"
#include "face-table.h"
#include "app.h"
#include "netif.h"
#include "l2.h"
#include "pit.h"
#include "fib.h"
#include "cs.h"
#include "forwarding-strategy.h"
#include "encoding/ndn-constants.h"
#include "encoding/name.h"
#include "encoding/interest.h"
#include "encoding/data.h"
#include "nfl-constant.h"
#include "msg-type.h"
#include "bootstrap.h"
#include "discovery.h"
//#include "nfl-block.h"
#define ENABLE_DEBUG 1
#include <debug.h>
#include <thread.h>
#include <timex.h>
#include <xtimer.h>

#define NFL_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#define NFL_PRIO              (THREAD_PRIORITY_MAIN - 3)
#define NFL_MSG_QUEUE_SIZE    (8U)

#if ENABLE_DEBUG
static char _stack[NFL_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[NFL_STACK_SIZE];
#endif

kernel_pid_t nfl_pid = KERNEL_PID_UNDEF;

kernel_pid_t nfl_bootstrap_pid = KERNEL_PID_UNDEF;
char bootstrap_stack[THREAD_STACKSIZE_MAIN];

kernel_pid_t nfl_discovery_pid = KERNEL_PID_UNDEF;
char discovery_stack[THREAD_STACKSIZE_MAIN];
nfl_subprefix_entry_t _subprefix_table[NFL_SUBPREFIX_ENTRIES_NUMOF];
nfl_service_entry_t _service_table[NFL_SERVICE_ENTRIES_NUMOF];
nfl_identity_entry_t _identity_table[NFL_IDENTITY_ENTRIES_NUMOF];
static msg_t query;

//below are the tables and tuples NFL thread need to maintain
static nfl_bootstrap_tuple_t* bootstrapTuple = NULL;

static int _start_bootstrap(void* ptr)
{
    //ptr pointed to a struct have three component: BKpub, BKpri, m_host
    
    //assign value
    msg_t send, reply;
    reply.content.ptr = NULL;
    nfl_bootstrap_pid = thread_create(bootstrap_stack, sizeof(bootstrap_stack),
                            THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, ndn_bootstrap, ptr, "nfl-bootstrap");
    //this thread directly registerd on ndn core thread as a application
    send.content.ptr = reply.content.ptr;

    uint32_t seconds = 2;
    xtimer_sleep(seconds); //we need some delay to achieve syc comm
    msg_send_receive(&send, &reply, nfl_bootstrap_pid);
    
    //store the ipc message in nfl maintained tuple 
    bootstrapTuple = reply.content.ptr;
    ndn_block_t* m_cert = bootstrapTuple->anchor_cert;
    ndn_block_t name;
    ndn_data_get_name(m_cert, &name);
    DEBUG("anchor certificate received through ipc tunnel, name = ");
    ndn_name_print(&name);
    putchar('\n');
    return true;
}

static int _start_discovery(void)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //this thread directly registerd on ndn core thread as a application
    _send.content.ptr = _reply.content.ptr;

    msg_send_receive(&_send, &_reply, nfl_discovery_pid);

    DEBUG("NFL: Service Discovery start\n");
    return true;
}


static int _set_discovery_prefix(void* ptr)
{
    msg_t _send, _reply;
    _reply.content.ptr = NULL;

    //ptr should indicate a uri
    _send.content.ptr = ptr;
    _send.type = NFL_SET_DISCOVERY_PREFIX;
    msg_send_receive(&_send, &_reply, nfl_discovery_pid);

    return true;
}

static int _init_discovery(void)
{
    //pass bootstrapTuple to discovery scenario
    if(bootstrapTuple == NULL){
         DEBUG("NFL: haven't bootstrapped yet\n");
         return false;
    }

    nfl_discovery_pid = thread_create(discovery_stack, sizeof(discovery_stack),
                        THREAD_PRIORITY_MAIN - 1, THREAD_CREATE_STACKTEST, nfl_discovery, bootstrapTuple,
                        "nfl-discovery");
    return true;
}

/* Main event loop for NFL */
static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[NFL_MSG_QUEUE_SIZE];

    (void)args;
    msg_init_queue(msg_q, NFL_MSG_QUEUE_SIZE);

    //TODO: initialize the NFL here

    /* start event loop */
    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NFL_START_BOOTSTRAP:
                DEBUG("NFL: START_BOOTSTRAP message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                
                _start_bootstrap(msg.content.ptr);
                
                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);

                //ndn_pit_timeout((msg_t*)msg.content.ptr);
                break;

            case NFL_START_DISCOVERY:
                DEBUG("NFL: START_DISCOVERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                _start_discovery();
                
                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_START_DISCOVERY_QUERY:
                DEBUG("NFL: START_DISCOVERY_QUERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                msg_try_send(&msg, nfl_discovery_pid); //directly forward to discovery thread
                query = msg;//buffer the query message

                break;

            case NFL_START_DISCOVERY_QUERY_REPLY:
                DEBUG("NFL: START_DISCOVERY_QUERY_REPLY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                msg_reply(&query, &msg);

                break;

            case NFL_INIT_DISCOVERY:
                DEBUG("NFL: INIT_DISCOVERY message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                               
                _init_discovery();

                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_SET_DISCOVERY_PREFIX:
                DEBUG("NFL: SET_DISCOVERY_PREFIX message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                //ptr should point to a string
                _set_discovery_prefix(msg.content.ptr);
                
                reply.content.ptr = NULL; //to invoke the nfl caller process
                msg_reply(&msg, &reply);
                break;

            case NFL_EXTRACT_BOOTSTRAP_TUPLE:
                DEBUG("NFL: EXTRACT_BOOTSTRAP_TUPLE message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);
                reply.content.ptr = bootstrapTuple;           
                msg_reply(&msg, &reply);
                break;

            case NFL_EXTRACT_DISCOVERY_LIST:
                DEBUG("NFL: EXTRACT_DISCOVERY_LIST message received from pid %"
                      PRIkernel_pid "\n", msg.sender_pid);

                //extract the tuple
                reply.content.ptr = &_identity_table;           
                msg_reply(&msg, &reply);
                break;

            default:
                break;
        }
    }

    return NULL;
}


kernel_pid_t nfl_init(void)
{
    /* check if thread is already running */
    if (nfl_pid == KERNEL_PID_UNDEF) {
        /* start UDP thread */
        nfl_pid = thread_create(
            _stack, sizeof(_stack), NFL_PRIO,
            THREAD_CREATE_STACKTEST, _event_loop, NULL, "NFL");
    }
    return nfl_pid;
}

/** @} */
