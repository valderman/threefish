Threefish
=========

Haskell implementation of the Threefish block cipher and the Skein
hash function built on it.

For Skein 256, this is about 50% slower than the wrapped C version in the
`skein` package, so if you're not after the block cipher you should just use
that package instead. The 512 bit versions are written in pure Haskell at the
moment, and are even slower.
