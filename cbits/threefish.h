#ifndef _THREEFISH_H
#define _THREEFISH_H

typedef unsigned long long W64;
extern W64 key_const;
#define rl(x, b) (((x) << ((b) & 63)) | ((x) >> ((64-(b)) & 63)))
#define rr(x, b) (((x) >> ((b) & 63)) | ((x) << ((64-(b)) & 63)))

typedef enum {
  T_KEY = 0,
  T_CONFIG = 4,
  T_PERSONALIZATION = 8,
  T_PUBKEY = 12,
  T_KEYIDENTIFIER = 16,
  T_NONCE = 20,
  T_MSG = 48,
  T_OUT = 63
} UBIType;

void encrypt256(W64* key, W64 t0, W64 t1, W64* in, W64* out);
void decrypt256(W64* key, W64 t0, W64 t1, W64* in, W64* out);
void hash256(W64* key, W64 len, W64* data, int outlen, W64* out);

inline void init_tweak(UBIType type, W64* t);
inline void mk_config_tweak(W64* t);
inline void set_type(UBIType type, W64* t);
inline void set_first(unsigned char first, W64* t);
inline void set_last(unsigned char last, W64* t);
inline void add_bytes(W64 bytes, W64* t);

#endif
