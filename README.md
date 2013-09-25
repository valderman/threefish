Threefish
=========

Haskell implementation of the Threefish block cipher and the Skein
hash function built on it. Skein is usable in "normal" mode, as well as for
Skein-MAC and as a cryptographically secure PRNG.

For Skein 256, this is about 50% slower than the wrapped C version in the
`skein` package, so if you're not after the block cipher you should just use
that package instead. The 512 bit version is written in pure Haskell at the
moment, and is quite a bit slower.
