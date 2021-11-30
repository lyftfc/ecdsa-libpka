#include "ecdsa_utils.h"
#include "testvec.h"
#include <stdio.h>
#include <time.h>

// Workaround for IntelliSense include issue
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID ((clockid_t) 2)
#endif

#define NUM_HWR 8
#define NUM_Q   (NUM_HWR * 1)
#define BATCH   (NUM_HWR * 6)  // Max NUM_HWR * 10
#define FIX_K   1
#define VERBOSE 0

int main() {
    // Initialize the instance
    ecdsa_inst_t *ecdsa = ecdsa_init(__FILE__,
        EC_SECP256R1, false, NUM_HWR, NUM_Q);
    if (ecdsa == NULL) return -1;
    pka_operand_t *hash = ecdsa_make_operand(ecdsa, P256_hash, 32);
    ecdsa->priv_key = ecdsa_make_operand(ecdsa, P256_private_key, 32);
#if (VERBOSE)
    ecdsa_print_operand("Digest", hash);
    ecdsa_print_operand("PrvKey", ecdsa->priv_key);
#endif

    // (Optional) use constant k value
#if (FIX_K)
    pka_operand_t *fixedK = ecdsa_make_operand(ecdsa, P256_k, 32);
#if (VERBOSE)
    pka_operand_t *gldR = ecdsa_make_operand(ecdsa, P256_r, 32);
    pka_operand_t *gldS = ecdsa_make_operand(ecdsa, P256_s, 32);
    ecdsa_print_operand("k(fix)", fixedK);
    ecdsa_print_operand("R(gld)", gldR);
    ecdsa_print_operand("S(gld)", gldS);
#endif
#endif

    // Initialize the worker and submit hash
    dsa_signature_t signs[BATCH];
    ecdsa_worker_t *wrkr = ecdsa_worker_init(ecdsa, NUM_Q);
    struct timespec tBegin, tEnd;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tBegin);
    for (int i = 0; i < BATCH; i++) {
#if (FIX_K)
        int rc = ecdsa_sign_hash(wrkr, hash, fixedK);
#else
        int rc = ecdsa_sign_hash(wrkr, hash, NULL);
#endif
        if (rc == ECDSA_FAIL) {
            printf("Error submitting hash for signing.\n");
            return -1;
        }
    }

    // Fetch the results
    int gotRes = 0;
    while (gotRes < BATCH) {
        uint32_t nres = ecdsa_get_signatures(wrkr, signs, BATCH, 0);
#if (VERBOSE)
        if (nres != 0) printf("\nGot %u results\n", nres);
        for (int i = 0; i < nres; i++) {
            ecdsa_print_operand("\nR", &signs[i].r);
            ecdsa_print_operand("S", &signs[i].s);
#else
        for (int i = 0; i < nres; i++) {
            if (ecdsa_check_sign(&signs[i]) == ECDSA_FAIL) {
                printf("Got failed signature. Quitting.\n");
                return -1;
            }
#endif
            ecdsa_result_free(&signs[i]);
        }
        gotRes += nres;
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tEnd);
    long nsDuration = (tEnd.tv_sec - tBegin.tv_sec) * (long)1e9 +
        (tEnd.tv_nsec - tBegin.tv_nsec);
    printf("%.2f us per sign\n", nsDuration / 1000.0 / BATCH);
    // ~35.5 us/sign on BF2 with (40, 4, 4)

    // Releasing resources
    ecdsa_worker_free(wrkr);
    ecdsa_operand_free(hash);
#if (FIX_K)
    ecdsa_operand_free(fixedK);
#if (VERBOSE)
    ecdsa_operand_free(gldR);
    ecdsa_operand_free(gldS);
#endif
#endif
    ecdsa_free(ecdsa);
    printf("Done.\n");
    return 0;
}