#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pka.h"

#include "ec_curves.h"
#include "testvec.h"

static void make_operand_buf(pka_operand_t *operand,
                             uint8_t       *big_endian_buf_ptr,
                             uint32_t       buf_len)
{
    operand->buf_ptr = malloc(buf_len);
    memset(operand->buf_ptr, 0, buf_len);
    operand->buf_len    = buf_len;
    operand->actual_len = buf_len;
    // Now fill the operand buf.
    // PKA_ASSERT(buf_len <= operand->buf_len);
    if (operand->big_endian) {
        memcpy(operand->buf_ptr, big_endian_buf_ptr, buf_len);
    } else {    // little-endian, now fill the operand buf, but backwards.
        for (uint32_t idx = 0; idx < buf_len; idx++)
            operand->buf_ptr[idx] = big_endian_buf_ptr[(buf_len - 1) - idx];
    }
    operand->actual_len = buf_len;
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
    if (byte_len == 0)
        return 0;

    if (operand->big_endian)
    {
        byte_ptr = &operand->buf_ptr[0];
        if (byte_ptr[0] != 0)
            return byte_len;

        // Move forwards over all zero bytes.
        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr++;
            byte_len--;
        }
    }
    else // little-endian
    {
        // First find the most significant byte based upon the actual_len, and
        // then move backwards over all zero bytes.
        byte_ptr = &operand->buf_ptr[byte_len - 1];
        if (byte_ptr[0] != 0)
            return byte_len;

        while ((byte_ptr[0] == 0) && (1 <= byte_len))
        {
            byte_ptr--;
            byte_len--;
        }
    }

    return byte_len;
}

uint8_t is_zero(pka_operand_t *operand)
{
    uint32_t len;

    len = operand_byte_len(operand);
    if (len == 0)
        return 1;
    else if (len == 1)
        return operand->buf_ptr[0] == 0;
    else
        return 0;
}

pka_cmp_code_t pki_compare(pka_operand_t *left, pka_operand_t *right)
{
    uint32_t left_len, right_len, idx;
    uint8_t *left_buf_ptr, *right_buf_ptr;

    if (is_zero(left))
    {
        if (is_zero(right))
            return RC_COMPARE_EQUAL;
        else
            return RC_LEFT_IS_SMALLER;
    }
    else if (is_zero(right))
        return RC_RIGHT_IS_SMALLER;

    left_len      = left->actual_len;
    right_len     = right->actual_len;
    left_buf_ptr  = left->buf_ptr;
    right_buf_ptr = right->buf_ptr;

    // Start the comparison at the most significant end which is at the
    // highest idx.  But first we need to skip any leading zeros!
    left_buf_ptr = &left_buf_ptr[left_len - 1];
    while ((left_buf_ptr[0] == 0) && (2 <= left_len))
    {
        left_buf_ptr--;
        left_len--;
    }

    right_buf_ptr = &right_buf_ptr[right_len - 1];
    while ((right_buf_ptr[0] == 0) && (2 <= right_len))
    {
        right_buf_ptr--;
        right_len--;
    }

    if (left_len < right_len)
        return RC_LEFT_IS_SMALLER;
    else if (right_len < left_len)
        return RC_RIGHT_IS_SMALLER;

    for (idx = 1; idx <= left_len; idx++)
    {
        if (left_buf_ptr[0] < right_buf_ptr[0])
            return  RC_LEFT_IS_SMALLER;
        else if (left_buf_ptr[0] > right_buf_ptr[0])
            return RC_RIGHT_IS_SMALLER;

        left_buf_ptr--;
        right_buf_ptr--;
    }

    return RC_COMPARE_EQUAL;
}

void print_operand(const char *info, pka_operand_t *oprd)
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

int main() {
    // The secp256r1 curve
    ecc_curve_t *p256r1 = make_ecc_curve(P256_p, P256_a, P256_b, P256_W);
    ecc_point_t *p256r1_G = make_ecc_point(p256r1, P256_xg, P256_yg, P256_W);
    pka_operand_t *p256r1_n = make_operand(P256_n, P256_W);

    // The test case (as of in pka_test_validation.c)
    // priv_key: test_operands[40]
    pka_operand_t *tc_privkey = make_operand(P256_private_key, P256_W);
    // pub_key: test_ecc_points[40]
    ecc_point_t *tc_pubkey = make_ecc_point(p256r1,
            P256_public_key_x, P256_public_key_y, P256_W);
    // hash: test_operands[41]
    pka_operand_t *tc_hash = make_operand(P256_hash, P256_W);
    print_operand("hash", tc_hash);
    // k: test_operands[42]
    pka_operand_t *tc_k = make_operand(P256_k, P256_W);
    // gld_sig: test_signatures[40]
    dsa_signature_t *tc_gld = make_dsa_signature(P256_r, P256_s, P256_W);

    // Running the test on single-thread
    pka_instance_t inst = pka_init_global(__FILE__,
        PKA_F_PROCESS_MODE_SINGLE + PKA_F_SYNC_MODE_ENABLE,
        1, 1, 32 << 14, 32 << 12);  // As in pka_test_validation:main()
    pka_handle_t handle = pka_init_local(inst);
    uint32_t req_count = pka_request_count(handle);
    printf("Request count: %u\n", req_count);
    pka_result_code_t ret = pka_ecdsa_signature_generate(
        handle, NULL, p256r1, p256r1_G, p256r1_n,
        tc_privkey, tc_hash, tc_k
    );
    if (ret != RC_NO_ERROR) {
        printf("Failed to generate signature.\n");
        return EXIT_FAILURE;
    }

    // Get the result and verify it
    pka_results_t sig;
    uint8_t sig_r[P256_W], sig_s[P256_W];
    memset(&sig, 0, sizeof(sig));
    init_operand(&sig.results[0], sig_r, P256_W);
    init_operand(&sig.results[1], sig_s, P256_W);

    req_count = pka_request_count(handle);
    if (req_count) {
        printf("Request count: %u\n", req_count);
        while (!pka_has_avail_result(handle));
        pka_get_result(handle, &sig);
        printf("Opcode: 0x%X\n", sig.opcode);

        print_operand("computed r", &sig.results[0]);
        print_operand("expected r", &tc_gld->r);
        if (pki_compare(&sig.results[0], &tc_gld->r) == RC_COMPARE_EQUAL)
            printf("r is correct\n");
        else printf("r is incorrect\n");
        print_operand("computed s", &sig.results[1]);
        print_operand("expected s", &tc_gld->s);
        if (pki_compare(&sig.results[1], &tc_gld->s) == RC_COMPARE_EQUAL)
            printf("s is correct\n");
        else printf("s is incorrect\n");
    } else
        printf("Failed to optain results.\n");

    pka_term_local(handle);
    pka_term_global(inst);
    return EXIT_SUCCESS;
    
}