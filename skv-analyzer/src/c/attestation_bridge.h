#ifndef SKV_ATTESTATION_BRIDGE_H
#define SKV_ATTESTATION_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if attestation token passes validation, otherwise 0.
// expected_nonce can be NULL when nonce checking is not required.
int skv_validate_attestation_token(
    const char *token_path,
    int required_ring,
    long max_age_sec,
    const char *expected_nonce,
    const char *replay_state_path
);

#ifdef __cplusplus
}
#endif

#endif
