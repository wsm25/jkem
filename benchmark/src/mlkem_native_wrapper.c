#include <stdint.h>

#include "mlkem/mlkem_native.h"

int bench_mlkem_native_keypair_derand(uint8_t *pk, uint8_t *sk,
                                      const uint8_t *coins) {
  return PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(pk, sk, coins);
}

int bench_mlkem_native_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                  const uint8_t *coins) {
  return PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(ct, ss, pk, coins);
}

int bench_mlkem_native_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return PQCP_MLKEM_NATIVE_MLKEM512_dec(ss, ct, sk);
}
