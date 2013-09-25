#include "threefish.h"
#include <string.h>

#include <stdio.h>

void hash256(W64* key, W64 len, W64* data, int outlen, W64* out) {
  static W64 zeroes[4] = {0,0,0,0};
  W64 config[4] = {0x0000000133414853, outlen*8, 0, 0};
  W64 tweak[2];
  W64 buf[4];
  W64 k[4] = {0,0,0,0};
  W64 lastlen = len % 32;
  if(lastlen == 0 && len != 0) {
    lastlen = 32;
  }

  /* Set up initial state */
  if(key != NULL) {
    init_tweak(T_KEY, tweak);
    set_last(1, tweak);
    add_bytes(32, tweak);
    encrypt256(zeroes, tweak[0], tweak[1], key, k);
    k[0] ^= key[0]; k[1] ^= key[1]; k[2] ^= key[2]; k[3] ^= key[3];
  }
  mk_config_tweak(tweak);
  add_bytes(32, tweak);
  encrypt256(k, tweak[0], tweak[1], config, buf);
  k[0] = config[0] ^ buf[0];
  k[1] = config[1] ^ buf[1];
  k[2] = config[2] ^ buf[2];
  k[3] = config[3] ^ buf[3];

  init_tweak(T_MSG, tweak);
  while(len > 32) {
    add_bytes(32, tweak);
    encrypt256(k, tweak[0], tweak[1], data, buf);
    set_first(0, tweak);
    k[0] = buf[0] ^ *data; ++data;
    k[1] = buf[1] ^ *data; ++data;
    k[2] = buf[2] ^ *data; ++data;
    k[3] = buf[3] ^ *data; ++data;
    len -= 32;
  }

  /* Process last block */
  add_bytes(lastlen, tweak);
  set_last(1, tweak);
  buf[0] = buf[1] = buf[2] = buf[3] = 0;
  memcpy(buf, data, lastlen);
  encrypt256(k, tweak[0], tweak[1], buf, k);
  k[0] ^= buf[0];
  k[1] ^= buf[1];
  k[2] ^= buf[2];
  k[3] ^= buf[3];

  /* Output pass */
  init_tweak(T_OUT, tweak);
  set_last(1, tweak);
  add_bytes(8, tweak);
  encrypt256(k, tweak[0], tweak[1], zeroes, out);
}
