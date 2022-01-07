#include "ecdsa_utils.h"
#include "testvec.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Workaround for IntelliSense include issue
#ifndef CLOCK_PROCESS_CPUTIME_ID
#define CLOCK_PROCESS_CPUTIME_ID ((clockid_t) 2)
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC ((clockid_t) 1)
#endif

#define CLOCK_ID    CLOCK_MONOTONIC

#define NUM_HWR 8
#define N_TEST  (20000 * NUM_HWR)
#define NUM_Q   (NUM_HWR * 1)
// #define S_CAP   (NUM_HWR * 5)  // Max NUM_HWR * 6
#define S_CAP   48
#define PGEN_K  1
#define VERBOSE 0

#define N_DLYREC    16384    // Must be 2^n
#if (N_DLYREC > N_TEST)
#error "More records than number of tests."
#endif

// Macro function calculating time duration in ns from x to y
#define TIMEDIFF_NS(x, y) \
    (((y).tv_sec - (x).tv_sec) * (long)1e9 + ((y).tv_nsec - (x).tv_nsec))

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

    // Signing delay collection
    struct timespec submit_ts[N_DLYREC];
    long delay_ns[N_DLYREC];
    const unsigned int dlyrec_mask = N_DLYREC - 1;

    // Initialize the worker and stream
    ecdsa_worker_t *wrkr = ecdsa_worker_init(ecdsa, NUM_Q);
    if (wrkr == NULL) return -1;
    ecdsa_stream_t *stream = ecdsa_stream_init(wrkr, S_CAP, PGEN_K);
    if (stream == NULL) return -1;
    ecdsa_worker_flush(wrkr);
    uint32_t totalRes = 0, totalWritten = 0;
    struct timespec tBegin, tEnd, tCurr;
    clock_gettime(CLOCK_ID, &tBegin);

    while (totalRes < N_TEST) {
        uint32_t nres;
        dsa_signature_t *res;
        if (totalWritten < N_TEST) {
            ecdsa_ret_t rc = ecdsa_stream_enqueue(stream, hash);
            if (rc == ECDSA_SUCC) {
                clock_gettime(CLOCK_ID,
                    &(submit_ts[totalWritten & dlyrec_mask]));
                totalWritten++;
            }
        }
        nres = ecdsa_stream_dequeue(stream, &res);
        clock_gettime(CLOCK_ID, &tCurr);
        for (int i = 0; i < nres; i++) {
            unsigned int recid = (totalRes + i) & dlyrec_mask;
            delay_ns[recid] = TIMEDIFF_NS(submit_ts[recid], tCurr);
        }
        totalRes += nres;
        if (totalRes > totalWritten) {
            printf("ERR: more returned results than written. Stop.\n");
            exit(1);
        }
    }

    clock_gettime(CLOCK_ID, &tEnd);
    long nsDuration = TIMEDIFF_NS(tBegin, tEnd);
    printf("%.2f us per sign.\n", nsDuration / 1000.0 / N_TEST);
    printf("Thrp: %.2f op/s\n", N_TEST * 1.0e9 / nsDuration);

    double delay_sum = 0;
    long delay_min = delay_ns[0], delay_max = delay_ns[0];
    for (int i = 0; i < N_DLYREC; i++) {
        delay_sum += delay_ns[i];
        delay_min = delay_ns[i] < delay_min ? delay_ns[i] : delay_min;
        delay_max = delay_ns[i] > delay_max ? delay_ns[i] : delay_max;
    }
    printf("Latency (us): min=%.2f max=%.2f avg=%.2f\n",
        delay_min / 1e3, delay_max / 1e3, delay_sum / N_DLYREC / 1e3);

    // Check if there are more results
    nanosleep(&(struct timespec){0, 1000000}, NULL);
    dsa_signature_t *res;
    uint32_t rem = ecdsa_stream_dequeue(stream, &res);
    if (rem != 0)
        printf("Warning: %u more results than expected\n", rem);

    // Releasing resources
    ecdsa_stream_free(stream);
    ecdsa_worker_free(wrkr);
    ecdsa_operand_free(hash);
    ecdsa_free(ecdsa);
    printf("Done.\n");
    return 0;
}