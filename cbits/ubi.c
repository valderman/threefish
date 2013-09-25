#include "threefish.h"

inline void init_tweak(UBIType type, W64* t) {
  t[0] = 0;
  t[1] = 0;
  set_first(1, t);
  set_type(type, t);
}

inline void mk_config_tweak(W64* t) {
  init_tweak(T_CONFIG, t);
  set_last(1, t);
}

inline void set_type(UBIType type, W64* t) {
  t[1] = (((W64)type) << 56) | (t[1] & ~(((W64)63) << 56));
}

inline void set_first(unsigned char first, W64* t) {
  if(first) {
    t[1] |= (((W64)1) << 62);
  } else {
    t[1] &= ~(((W64)1) << 62);
  }
}

inline void set_last(unsigned char last, W64* t) {
  if(last) {
    t[1] |= (((W64)1) << 63);
  } else {
    t[1] &= ~(((W64)1) << 63);
  }
}

inline void add_bytes(W64 bytes, W64* t) {
  t[0] += bytes;
}
