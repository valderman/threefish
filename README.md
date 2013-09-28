Threefish
=========

Haskell implementation of the Threefish block cipher and the various fun
things you can do with it as specified by the Skein 1.3 paper.
This currently includes:

* Threefish block cipher
* Skein hash function
* Skein-MAC
* PRNG
* Stream cipher
* Key derivation function

There's also a convenience module that puts it all together, for a simple
interface to authenticated encryption.

For Skein 256, this package is about 35% slower than the wrapped C version in
the `skein` package, so if you're only after the hash function you should use
that package instead. The 512 bit variant is written in pure Haskell, and
quite a bit slower still.
