#include <stdint.h>

#define MLK_CHECK_APIS
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem/mlkem_native.h"
#include "mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED

#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem/mlkem_native.h"
#include "mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem/mlkem_native.h"
#include "mlkem/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET

int bench_mlkem_native_keypair_derand(uint8_t *pk, uint8_t *sk,
                                      const uint8_t *coins) {
  return mlkem512_keypair_derand(pk, sk, coins);
}

int bench_mlkem_native_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                  const uint8_t *coins) {
  return mlkem512_enc_derand(ct, ss, pk, coins);
}

int bench_mlkem_native_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  return mlkem512_dec(ss, ct, sk);
}

int bench_mlkem_native768_keypair_derand(uint8_t *pk, uint8_t *sk,
                                         const uint8_t *coins) {
  return mlkem768_keypair_derand(pk, sk, coins);
}

int bench_mlkem_native768_enc_derand(uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk,
                                     const uint8_t *coins) {
  return mlkem768_enc_derand(ct, ss, pk, coins);
}

int bench_mlkem_native768_dec(uint8_t *ss, const uint8_t *ct,
                              const uint8_t *sk) {
  return mlkem768_dec(ss, ct, sk);
}

int bench_mlkem_native1024_keypair_derand(uint8_t *pk, uint8_t *sk,
                                          const uint8_t *coins) {
  return mlkem1024_keypair_derand(pk, sk, coins);
}

int bench_mlkem_native1024_enc_derand(uint8_t *ct, uint8_t *ss,
                                      const uint8_t *pk,
                                      const uint8_t *coins) {
  return mlkem1024_enc_derand(ct, ss, pk, coins);
}

int bench_mlkem_native1024_dec(uint8_t *ss, const uint8_t *ct,
                               const uint8_t *sk) {
  return mlkem1024_dec(ss, ct, sk);
}
