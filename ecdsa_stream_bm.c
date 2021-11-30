#include "ecdsa_utils.h"
#include "testvec.h"
#include <stdio.h>
#include <time.h>

// Workaround for IntelliSense include issue
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID ((clockid_t) 2)
#endif

#define N_TEST  20000
#define NUM_HWR 8
#define NUM_Q   (NUM_HWR * 1)
#define S_CAP   (NUM_HWR * 5)  // Max NUM_HWR * 6
#define PGEN_K  1
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

    // Initialize the worker and stream
    ecdsa_worker_t *wrkr = ecdsa_worker_init(ecdsa, NUM_Q);
    if (wrkr == NULL) return -1;
    ecdsa_stream_t *stream = ecdsa_stream_init(wrkr, S_CAP, PGEN_K);
    if (stream == NULL) return -1;
    uint32_t totalRes = 0, totalWritten = 0;
    struct timespec tBegin, tEnd;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tBegin);

    while (totalRes < N_TEST) {
        uint32_t nres;
        dsa_signature_t *res;
        pka_operand_t *h = (totalWritten < N_TEST) ? hash : NULL;
        ecdsa_ret_t rc = ecdsa_stream_enqdeq(stream, h, &res, &nres);
        if (rc == ECDSA_SUCC) totalWritten++;
        totalRes += nres;
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tEnd);
    long nsDuration = (tEnd.tv_sec - tBegin.tv_sec) * (long)1e9 +
        (tEnd.tv_nsec - tBegin.tv_nsec);
    printf("%.2f us per sign.\n", nsDuration / 1000.0 / N_TEST);

    // Releasing resources
    ecdsa_stream_free(stream);
    ecdsa_worker_free(wrkr);
    ecdsa_operand_free(hash);
    ecdsa_free(ecdsa);
    printf("Done.\n");
    return 0;
}