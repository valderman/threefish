{-# LANGUAGE BangPatterns #-}
module Crypto.Threefish.Mix where
import Data.Word
import Data.Bits

{-# INLINE mix #-}
mix :: Word64 -> Word64 -> Int -> (Word64, Word64)
mix !a !b !r =
  case a + b of
    a' -> (a', rotateL b r `xor` a')

{-# INLINE mixKey #-}
mixKey :: Word64 -> Word64 -> Int -> Word64 -> Word64 -> (Word64, Word64)
mixKey !a !b !r !k0 !k1 =
    (a', rotateL b' r `xor` a')
  where
    !b' = b + k1
    !a' = a + b' + k0

{-# INLINE unmix #-}
unmix :: Word64 -> Word64 -> Int -> (Word64, Word64)
unmix !a !b !r =
  case rotateR (b `xor` a) r of
    b' -> (a - b', b')

{-# INLINE unmixKey #-}
unmixKey :: Word64 -> Word64 -> Int -> Word64 -> Word64 -> (Word64, Word64)
unmixKey !a !b !r !k0 !k1 =
    (a', b' - k1)
  where
    !b' = rotateR (b `xor` a) r
    !a' = a - (b' + k0)
