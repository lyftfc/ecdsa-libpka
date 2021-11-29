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
uint32_t ecdsa_get_signatures(ecdsa_worker_t *worker,
    dsa_signature_t *signs, uint32_t maxNumSigns);

// Check if a signature is error-free
ecdsa_ret_t ecdsa_check_sign(dsa_signature_t *sign);

// Free result memory allocated by ecdsa_get_results
void ecdsa_result_free(dsa_signature_t *sign);

// Print an ECDSA operand with explanation info
void ecdsa_print_operand(const char *info, pka_operand_t *opr);

#endif  // _ECDSA_UTILS_H_