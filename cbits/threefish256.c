#include "threefish.h"

W64 key_const = 0x1BD11BDAA9FC1A22;

void encrypt256(W64* key, W64 t0, W64 t1, W64* in, W64* out) {
  int r;
  W64 k4 = key[0] ^ key[1] ^ key[2] ^ key[3] ^ key_const;
  W64 ks[5] = {key[0], key[1], key[2], key[3], k4};
  W64 ts[3] = {t0, t1, t0 ^ t1};
  W64 a = in[0] + ks[0];
  W64 b = in[1] + ks[1] + ts[0];
  W64 c = in[2] + ks[2] + ts[1];
  W64 d = in[3] + ks[3];

  for(r = 2; r < 20; r += 2) {
    a += b; b = rl(b, 14) ^ a;
    c += d; d = rl(d, 16) ^ c;
    a += d; d = rl(d, 52) ^ a;
    c += b; b = rl(b, 57) ^ c;
    a += b; b = rl(b, 23) ^ a;
    c += d; d = rl(d, 40) ^ c;
    a += d; d = rl(d,  5) ^ a;
    c += b; b = rl(b, 37) ^ c;
    a += ks[(r-1) % 5];
    b += ks[r % 5] + ts[(r-1) % 3];
    c += ks[(r+1) % 5] + ts[r % 3];
    d += ks[(r+2) % 5] + (r-1);
    a += b; b = rl(b, 25) ^ a;
    c += d; d = rl(d, 33) ^ c;
    a += d; d = rl(d, 46) ^ a;
    c += b; b = rl(b, 12) ^ c;
    a += b; b = rl(b, 58) ^ a;
    c += d; d = rl(d, 22) ^ c;
    a += d; d = rl(d, 32) ^ a;
    c += b; b = rl(b, 32) ^ c;
    a += ks[r % 5];
    b += ks[(r+1) % 5] + ts[r % 3];
    c += ks[(r+2) % 5] + ts[(r+1) % 3];
    d += ks[(r+3) % 5] + r;
  }
  out[0] = a; out[1] = b; out[2] = c; out[3] = d;
}

void decrypt256(W64* key, W64 t0, W64 t1, W64* in, W64* out) {
  int r;
  W64 k4 = key[0] ^ key[1] ^ key[2] ^ key[3] ^ key_const;
  W64 ks[5] = {key[0], key[1], key[2], key[3], k4};
  W64 ts[3] = {t0, t1, t0 ^ t1};
  W64 a = in[0] + ks[0];
  W64 b = in[1] + ks[1] + ts[0];
  W64 c = in[2] + ks[2] + ts[1];
  W64 d = in[3] + ks[3];

  for(r = 18; r >= 2; r -= 2) {
    a -= ks[r % 5];
    b -= ks[(r+1) % 5] + ts[r % 3];
    c -= ks[(r+2) % 5] + ts[(r+1) % 3];
    d -= ks[(r+3) % 5] + r;
    d = rr(d^a, 32); a -= d;
    b = rr(b^c, 32); c -= b;
    b = rr(b^a, 58); a -= b;
    d = rr(d^c, 22); c -= d;
    d = rr(d^a, 46); a -= d;
    b = rr(b^c, 12); c -= b;
    b = rr(b^a, 25); a -= b;
    d = rr(d^c, 33); c -= d;
    a -= ks[(r-1) % 5];
    b -= ks[r % 5] + ts[(r-1) % 3];
    c -= ks[(r+1) % 5] + ts[r % 3];
    d -= ks[(r+2) % 5] + (r-1);
    d = rr(d^a,  5); a -= d;
    b = rr(b^c, 37); c -= b;
    b = rr(b^a, 23); a -= b;
    d = rr(d^c, 40); c -= d;
    d = rr(d^a, 52); a -= d;
    b = rr(b^c, 57); c -= b;
    b = rr(b^a, 14); a -= b;
    d = rr(d^c, 16); c -= d;
  }
  out[0] = a - ks[0];           out[1] = b - (ks[1] + ts[0]);
  out[2] = c - (ks[2] + ts[1]); out[3] = d - ks[3];
}
