Threefish
=========

Haskell implementation of the Threefish block cipher and the Skein
hash function built on it.

For Skein, this is about 12 times slower than the wrapped C version in the
`skein` package, so if you're not after the block cipher or need an
implementation that doesn't depend on any non-Haskell code, you should just
use that package instead.
