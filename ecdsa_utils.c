#include "ecdsa_utils.h"
#include "ec_curves.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CMD_Q_SIZE  (32 << 14)
#define RSLT_Q_SIZE (32 << 12)

/* Functions adapted from Mellanox's PKA library testing code */

static void fill_operand(pka_operand_t *operand, const uint8_t *buf_ptr,
                         uint32_t buf_len, uint8_t buf_is_big_endian)
{
    // Make sure them are 1 or 0 so we can equate them
    uint8_t dstEnd = operand->big_endian ? 1 : 0;
    uint8_t srcEnd = buf_is_big_endian ? 1 : 0;
    if (operand->big_endian == srcEnd) {
        memcpy(operand->buf_ptr, buf_ptr, buf_len);
    } else {    // Different endianess, fill the operand buf backwards.
        for (uint32_t idx = 0; idx < buf_len; idx++)
            operand->buf_ptr[idx] = buf_ptr[(buf_len - 1) - idx];
    }
    operand->actual_len = buf_len;
}

static void make_operand_buf(pka_operand_t *operand,
                             uint8_t       *big_endian_buf_ptr,
                             uint32_t       buf_len)
{
    operand->buf_ptr = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    // Now fill the operand buf.
    fill_operand(operand, big_endian_buf_ptr, buf_len, 1);
}

ecc_curve_t *make_ecc_curve(uint8_t *big_endian_buf_p_ptr,
                            uint8_t *big_endian_buf_a_ptr,
                            uint8_t *big_endian_buf_b_ptr,
                            uint32_t param_len)
{
    ecc_curve_t *curve;
    curve = malloc(sizeof(ecc_curve_t));
    memset(curve, 0, sizeof(ecc_curve_t));
    curve->p.big_endian = 0;
    curve->a.big_endian = 0;
    curve->b.big_endian = 0;
    make_operand_buf(&curve->p, big_endian_buf_p_ptr, param_len);
    make_operand_buf(&curve->a, big_endian_buf_a_ptr, param_len);
    make_operand_buf(&curve->b, big_endian_buf_b_ptr, param_len);
    return curve;
}

ecc_point_t *make_ecc_point(ecc_curve_t *curve,
                            uint8_t     *big_endian_buf_x_ptr,
                            uint8_t     *big_endian_buf_y_ptr,
                            uint32_t     buf_len)
{
    ecc_point_t *ecc_point;
    ecc_point = malloc(sizeof(ecc_point_t));
    memset(ecc_point, 0, sizeof(ecc_point_t));
    ecc_point->x.big_endian = 0;
    ecc_point->y.big_endian = 0;
    make_operand_buf(&ecc_point->x, big_endian_buf_x_ptr, buf_len);
    make_operand_buf(&ecc_point->y, big_endian_buf_y_ptr, buf_len);
    return ecc_point;
}

pka_operand_t *make_operand(uint8_t  *big_endian_buf_ptr,
                            uint32_t  buf_len)
{
    pka_operand_t *operand;
    operand = malloc(sizeof(pka_operand_t));
    memset(operand, 0, sizeof(pka_operand_t));
    operand->big_endian = 0;
    // Now init the operand buf.
    make_operand_buf(operand, big_endian_buf_ptr, buf_len);
    return operand;
}

void init_operand(pka_operand_t *operand,
                  uint8_t       *buf,
                  uint32_t       buf_len)
{
    memset(operand, 0, sizeof(pka_operand_t));
    memset(buf,     0, buf_len);
    operand->buf_ptr    = buf;
    operand->buf_len    = buf_len;
    operand->actual_len = 0;
    operand->big_endian = 0;
}

dsa_signature_t *make_dsa_signature(uint8_t *big_endian_buf_r_ptr,
                                    uint8_t *big_endian_buf_s_ptr,
                                    uint32_t param_len)
{
    dsa_signature_t *signature;
    signature = malloc(sizeof(dsa_signature_t));
    memset(signature, 0, sizeof(dsa_signature_t));
    signature->r.big_endian = 0;
    signature->s.big_endian = 0;
    make_operand_buf(&signature->r, big_endian_buf_r_ptr, param_len);
    make_operand_buf(&signature->s, big_endian_buf_s_ptr, param_len);
    return signature;
}

uint32_t operand_byte_len(pka_operand_t *operand)
{
    uint32_t byte_len;
    uint8_t *byte_ptr;
    byte_len = operand->actual_len;
    if (byte_len == 0) return 0;

    if (operand->big_endian) {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0) return byte_len;
        // Move forwards over all zero bytes.
        while ((byte_ptr[0] == 0) && (1 <= byte_len)) {
            byte_ptr++; byte_len--;
        }
    } else {    // little-endian
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0) return byte_len;
        while ((byte_ptr[0] == 0) && (1 <= byte_len)) {
            byte_ptr--; byte_len--;
        }
    }
    return byte_len;
}

uint8_t is_zero(pka_operand_t *operand)
{
    uint32_t len;
    len = operand_byte_len(operand);
    if (len == 0) return 1;
    else if (len == 1) return operand->buf_ptr[0] == 0;
    else return 0;
}

pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right)
{
    uint32_t left_len, right_len, idx;
    uint8_t *left_buf_ptr, *right_buf_ptr;

    if (is_zero(left)) {
        if (is_zero(right)) return RC_COMPARE_EQUAL;
        else return RC_LEFT_IS_SMALLER;
    } else if (is_zero(right)) return RC_RIGHT_IS_SMALLER;

    left_len      = left->actual_len;
    right_len     = right->actual_len;
    left_buf_ptr  = left->buf_ptr;
    right_buf_ptr = right->buf_ptr;

    // Start the comparison at the most significant end which is at the
    // highest idx.  But first we need to skip any leading zeros!
    left_buf_ptr = &left_buf_ptr[left_len - 1];
    while ((left_buf_ptr[0] == 0) && (2 <= left_len)) {
        left_buf_ptr--; left_len--;
    }
    right_buf_ptr = &right_buf_ptr[right_len - 1];
    while ((right_buf_ptr[0] == 0) && (2 <= right_len)) {
        right_buf_ptr--; right_len--;
    }

    if (left_len < right_len) return RC_LEFT_IS_SMALLER;
    else if (right_len < left_len) return RC_RIGHT_IS_SMALLER;

    for (idx = 1; idx <= left_len; idx++) {
        if (left_buf_ptr[0] < right_buf_ptr[0]) return RC_LEFT_IS_SMALLER;
        else if (left_buf_ptr[0] > right_buf_ptr[0]) return RC_RIGHT_IS_SMALLER;
        left_buf_ptr--; right_buf_ptr--;
    }
    return RC_COMPARE_EQUAL;
}

/* Wrapper ECDSA library implementation */

// Initialize ECDSA utility and the underlying pka_init_global
// returns NULL upon unsuccessful transaction
ecdsa_inst_t *ecdsa_init(const char *tag, ecdsa_curve_t curve,
    bool isSync, uint32_t numRing, uint32_t numQueues)
{
    pka_instance_t pka = pka_init_global(tag,
        PKA_F_PROCESS_MODE_SINGLE + 
        (isSync ? PKA_F_SYNC_MODE_ENABLE : PKA_F_SYNC_MODE_DISABLE),
        numRing, numQueues, CMD_Q_SIZE, RSLT_Q_SIZE);
    if (pka == PKA_INSTANCE_INVALID) return NULL;

    ecdsa_inst_t *inst = malloc(sizeof(ecdsa_inst_t));
    inst->pka_inst = pka;
    switch (curve){
    case EC_SECP256R1:
        inst->opr_width = P256_W;
        inst->curve = make_ecc_curve(P256_p, P256_a, P256_b, P256_W);
        inst->base = make_ecc_point(inst->curve, P256_xg, P256_yg, P256_W);
        inst->order = make_operand(P256_n, P256_W);
        // priv_key is not init here
        inst->priv_key = NULL;
        break;
    default:
        pka_term_global(pka);
        free(inst);
        return NULL;
    }
    return inst;
}

// Free and clean up the ECDSA utility and calls pka_term_global
void ecdsa_free(ecdsa_inst_t *inst)
{
    pka_term_global(inst->pka_inst);
    free(inst->curve->a.buf_ptr);
    free(inst->curve->b.buf_ptr);
    free(inst->curve->p.buf_ptr);
    free(inst->curve);
    free(inst->base->x.buf_ptr);
    free(inst->base->y.buf_ptr);
    free(inst->base);
    free(inst->order->buf_ptr);
    free(inst->order);
    if (inst->priv_key != NULL) {
        free(inst->priv_key->buf_ptr);
        free(inst->priv_key);
    }
}

// Initialize local worker that encapsulates one or more pka_handle_t
// returns NULL upon unsuccessful transaction
ecdsa_worker_t *ecdsa_worker_init(ecdsa_inst_t *inst, uint32_t numHdls)
{
    pka_handle_t *hdls = malloc(numHdls * sizeof(pka_handle_t));
    for (int i = 0; i < numHdls; i++) {
        hdls[i] = pka_init_local(inst->pka_inst);
        if (hdls[i] == PKA_HANDLE_INVALID) {
            for (i--; i >= 0; i--)
                pka_term_local(hdls[i]);
            free(hdls);
            return NULL;
        }
    }
    ecdsa_worker_t *worker = malloc(sizeof(ecdsa_worker_t));
    worker->handles = hdls;
    worker->num_hdls = numHdls;
    worker->inst = inst;
    worker->next_deq = 0;
    worker->next_enq = 0;
    return worker;
}

// Free and clean up the worker and its underlying PKA handle(s)
void ecdsa_worker_free(ecdsa_worker_t *worker)
{
    for (int i = 0; i < worker->num_hdls; i++)
        pka_term_local(worker->handles[i]);
    free(worker->handles);
    free(worker);
}

// Prepare an ECDSA operand, optionally with big-endian data in src (or empty)
pka_operand_t *ecdsa_make_operand(ecdsa_inst_t *inst,
    const uint8_t src[], uint32_t srcLen)
{
    pka_operand_t *oprd = malloc(sizeof(pka_operand_t));
    uint8_t *buf = malloc(inst->opr_width);
    init_operand(oprd, buf, inst->opr_width);
    // init_operand defaults to little-endian and src is big-endian
    if (src != NULL)
        fill_operand(oprd, src, srcLen, 1);
    return oprd;
}

// Free an ECDSA operand
void ecdsa_operand_free(pka_operand_t *oprd)
{
    free(oprd->buf_ptr);
    free(oprd);
}

// Submit a hash for signature, using random k if not provided
ecdsa_ret_t ecdsa_sign_hash(ecdsa_worker_t *worker,
    pka_operand_t *hash, pka_operand_t *rand)
{
    pka_operand_t *k = ecdsa_make_operand(worker->inst, NULL, 0);
    pka_handle_t curr_hdl = worker->handles[worker->next_enq];
    if (rand != NULL) {
        fill_operand(k, rand->buf_ptr, rand->actual_len, rand->big_endian);
    } else {
        // We generate one less byte of k so that it will be smaller than n
        pka_get_rand_bytes(curr_hdl,
            k->buf_ptr, worker->inst->opr_width - 1);
        k->actual_len = worker->inst->opr_width - 1;
    }
    int rc = pka_ecdsa_signature_generate(curr_hdl, k,
        worker->inst->curve,
        worker->inst->base, worker->inst->order,
        worker->inst->priv_key, hash, k);
    if (rc != 0) {  // We caught an error here
        ecdsa_operand_free(k);
        return ECDSA_FAIL;
    } else {
        worker->next_enq = (worker->next_enq == worker->num_hdls - 1) ?
            0 : worker->next_enq + 1;
        return ECDSA_SUCC;
    }
}

// Read at most maxNumSigns signatures into signs, returns actual number
// of results that are read. R and S are empty if that signing failed.
uint32_t ecdsa_get_signatures(ecdsa_worker_t *worker,
    dsa_signature_t *signs, uint32_t maxNumSigns)
{
    uint32_t count;
    for (count = 0; count < maxNumSigns; count++) {
        pka_handle_t hdl = worker->handles[worker->next_deq];
        if (!pka_has_avail_result(hdl)) break;
        pka_results_t res;
        for (int i = 0; i < 2; i++) {
            pka_operand_t *ptmp = ecdsa_make_operand(worker->inst, NULL, 0);
            res.results[i] = *ptmp;
            free(ptmp); // Only free the operand but not its buffer
        }
        pka_get_result(hdl, &res);
        signs[count].r = res.results[0];    // Allocated operand buffers goes here
        signs[count].s = res.results[1];
        free(res.user_data);    // Free the generated k previously passed in
        if (res.opcode != CC_ECDSA_GENERATE || res.status != RC_NO_ERROR) {
            // We got problem here so we mark this result invalid
            signs[count].r.actual_len = 0;
            signs[count].s.actual_len = 0;
        }
        worker->next_deq = (worker->next_deq == worker->num_hdls - 1) ?
            0 : worker->next_deq + 1;
    }
    return count;
}

// Check if a signature is error-free
ecdsa_ret_t ecdsa_check_sign(dsa_signature_t *sign)
{
    if (sign->r.actual_len == 0 || sign->s.actual_len == 0)
        return ECDSA_FAIL;
    else return ECDSA_SUCC;
}

// Free result memory allocated by ecdsa_get_results
void ecdsa_result_free(dsa_signature_t *sign)
{
    free(sign->r.buf_ptr);
    free(sign->s.buf_ptr);
}

// Print an ECDSA operand with explanation info
void ecdsa_print_operand(const char *info, pka_operand_t *oprd)
{
    printf("%s: ", info);
    uint32_t len = operand_byte_len(oprd);
    if (oprd->big_endian) {
        uint32_t ofs = oprd->actual_len - len;
        for (int i = 0; i < len; i++)
            printf("%02X ", oprd->buf_ptr[ofs + i]);
    } else {
        for (int i = len - 1; i >= 0; i--)
            printf("%02X ", oprd->buf_ptr[i]);
    }
    printf("\n");
}
