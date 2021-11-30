#ifndef _ECDSA_UTILS_H_
#define _ECDSA_UTILS_H_

#include "pka.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    pka_instance_t pka_inst;
    uint32_t opr_width;
    ecc_curve_t *curve;
    ecc_point_t *base;  // G point
    pka_operand_t *order;   // n of G
    pka_operand_t *priv_key;
} ecdsa_inst_t;

typedef struct {
    ecdsa_inst_t *inst;
    pka_handle_t *handles;
    uint32_t num_hdls;
    uint32_t next_enq, next_deq;
} ecdsa_worker_t;

typedef struct {
    ecdsa_worker_t *worker;
    uint32_t capacity, pending;
    uint8_t *k_pool, *hash_pool, *res_pool;
    pka_operand_t *k_arr, *hash_arr;
    dsa_signature_t *res_arr;
    uint32_t next_in;
    uint8_t is_pregen_k;
} ecdsa_stream_t;

typedef enum {
    EC_SECP256R1 = 0
} ecdsa_curve_t;

typedef enum {
    ECDSA_SUCC = 0,
    ECDSA_FAIL = 1
} ecdsa_ret_t;

// Initialize ECDSA utility and the underlying pka_init_global
// returns NULL upon unsuccessful transaction
ecdsa_inst_t *ecdsa_init(const char *tag, ecdsa_curve_t curve,
    bool isSync, uint32_t numRing, uint32_t numQueues);

// Free and clean up the ECDSA utility and calls pka_term_global
void ecdsa_free(ecdsa_inst_t *inst);

// Initialize local worker that encapsulates one or more pka_handle_t
// returns NULL upon unsuccessful transaction
ecdsa_worker_t *ecdsa_worker_init(ecdsa_inst_t *inst, uint32_t numHdls);

// Free and clean up the worker and its underlying PKA handle(s)
void ecdsa_worker_free(ecdsa_worker_t *worker);

// Prepare an ECDSA operand, optionally with big-endian data in src (or empty)
pka_operand_t *ecdsa_make_operand(ecdsa_inst_t *inst,
    const uint8_t src[], uint32_t srcLen);

// Free an ECDSA operand
void ecdsa_operand_free(pka_operand_t *oprd);

// Submit a hash for signature, using random k if not provided
ecdsa_ret_t ecdsa_sign_hash(ecdsa_worker_t *worker,
    pka_operand_t *hash, pka_operand_t *rand);

// Read at most maxNumSigns signatures into signs, returns actual number
// of results that are read. R and S are empty if that signing failed.
// If isSignsInited is set to non-zero, it tries to use buffers of signs.
uint32_t ecdsa_get_signatures(ecdsa_worker_t *worker,
    dsa_signature_t *signs, uint32_t maxNumSigns, uint8_t isSignsInited);

// Check if a signature is error-free
ecdsa_ret_t ecdsa_check_sign(dsa_signature_t *sign);

// Free result memory allocated by ecdsa_get_results
void ecdsa_result_free(dsa_signature_t *sign);

// Print an ECDSA operand with explanation info
void ecdsa_print_operand(const char *info, pka_operand_t *opr);

// ECDSA Streaming Interface
// Provides a higher-level interface wrapping the worker
// for high-performance continuous signing. It pre-allocates
// operand memories, but capacity is also limited by internal
// hardware ring queues.

// Initialize an ECDSA stream using a given worker & its instance
// capacity: maximum number of result-pending signings, fails if exceeding max
// pregen_k: boolean indicating if the random k should be pre-generated
// Pre-generation of k saves signing time, but severely impacts security.
ecdsa_stream_t *ecdsa_stream_init(ecdsa_worker_t *worker,
    uint32_t capacity, uint8_t pregen_k);

// Free a ECDSA streaming instance, does NOT free the underlying worker
void ecdsa_stream_free(ecdsa_stream_t *stream);

// Enqueue a hash value to the signing stream, fails if stream is full
// The operand is copied to the queue if success
ecdsa_ret_t ecdsa_stream_enqueue(ecdsa_stream_t *stream, pka_operand_t *hash);

// Dequeue available signatures to the result buffer, return number of results
// User is responsible for saving/copying results before the next call
uint32_t ecdsa_stream_dequeue(ecdsa_stream_t *stream, dsa_signature_t **res);

// Enqueue a hash value and dequeue available results, returns the enqueue result
ecdsa_ret_t ecdsa_stream_enqdeq(ecdsa_stream_t *stream,
    pka_operand_t *hash, dsa_signature_t **res, uint32_t *n_res);

#endif  // _ECDSA_UTILS_H_