#include "threefish.h"
#include <string.h>

void skein256_init(skein_t* ctx, W64* key, W64 outlen) {
  W64 config[4] = {0x0000000133414853, outlen, 0, 0};
  static W64 zeroes[4] = {0,0,0,0};

  /* Set up key if needed */
  if(key != NULL) {
    init_tweak(T_KEY, ctx->tweak);
    set_last(1, ctx->tweak);
    add_bytes(32, ctx->tweak);
    encrypt256(zeroes, ctx->tweak[0], ctx->tweak[1], key, ctx->key);
    ctx->key[0] ^= key[0];
    ctx->key[1] ^= key[1];
    ctx->key[2] ^= key[2];
    ctx->key[3] ^= key[3];
  } else {
    ctx->key[0] = 0; ctx->key[1] = 0; ctx->key[2] = 0; ctx->key[3] = 0;
  }

  /* Process config string */
  mk_config_tweak(ctx->tweak);
  add_bytes(32, ctx->tweak);
  encrypt256(ctx->key, ctx->tweak[0], ctx->tweak[1], config, ctx->key);
  ctx->key[0] ^= config[0];
  ctx->key[1] ^= config[1];
  ctx->key[2] ^= config[2];
  ctx->key[3] ^= config[3];
}

void skein256_update(skein_t* ctx, int firstlast, UBIType type, W64 len, W64* data) {
  W64 buf[4] = {0,0,0,0};
  W64* k = ctx->key;
  W64* tweak = ctx->tweak;
  int lastlen;

  /* Process message */
  if(firstlast & 1) {
    init_tweak(type, tweak);
  }
  /* If this is not the last update, don't do last block processing  */
  if(!(firstlast & 2) && len % 32 == 0) {
    ++len;
  }
  while(len > 32) {
    add_bytes(32, tweak);
    encrypt256(k, tweak[0], tweak[1], data, k);
    set_first(0, tweak);
    k[0] ^= *data; ++data;
    k[1] ^= *data; ++data;
    k[2] ^= *data; ++data;
    k[3] ^= *data; ++data;
    len -= 32;
  }

  /* Process last block */
  if(firstlast & 2) {
    lastlen = len % 32;
    if(lastlen == 0 && len > 0) {
      lastlen = 32;
    }
    add_bytes(lastlen, tweak);
    set_last(1, tweak);
    memcpy(buf, data, lastlen);
    encrypt256(k, tweak[0], tweak[1], buf, k);
    k[0] ^= buf[0];
    k[1] ^= buf[1];
    k[2] ^= buf[2];
    k[3] ^= buf[3];
  }
}

void skein256_output(skein_t* ctx, int from, int to, W64* out) {
  W64 buf[4] = {from,0,0,0};
  W64 *k = ctx->key;
  W64 *tweak = ctx->tweak;
  for(; from <= to; ++from) {
    init_tweak(T_OUT, tweak);
    set_last(1, tweak);
    add_bytes(8, tweak);
    encrypt256(k, tweak[0], tweak[1], buf, out);
    out += 4;
    ++buf[0];
  }
}
