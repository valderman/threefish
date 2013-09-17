{-# LANGUAGE BangPatterns #-}
-- | 512 bit Threefish.
module Crypto.Cipher.Threefish.Threefish512 where
import Data.Word
import Data.Bits
import Crypto.Cipher.Threefish.Mix
import Crypto.Cipher.Threefish.Common
import Data.Array.Unboxed
import Data.Serialize
import Control.Applicative

data Block512 = Block512 {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                deriving Eq

type Key512 = Block512

instance Show Block512 where
  show (Block512 a b c d e f g h) =
    showBytes a ++ showBytes b ++ showBytes c ++ showBytes d ++
    showBytes e ++ showBytes f ++ showBytes g ++ showBytes h

instance Serialize Block512 where
  put (Block512 a b c d e f g h) = do
    putWord64le a >> putWord64le b >> putWord64le c >> putWord64le d
    putWord64le e >> putWord64le f >> putWord64le g >> putWord64le h
  get =
    Block512 <$> get <*> get <*> get <*> get <*> get <*> get <*> get <*> get

-- | Rotational constants for TF512
rot :: UArray Word64 Int
rot = listArray (0,32) [46,36,19,37,33,27,14,42,17,49,36,39,44,9,54,56,
                        39,30,34,24,13,50,10,17,25,29,39,43,8,35,56,22]

-- | Encrypt a 512 bit Threefish block. Tweak may have any value without
--   compromising security.
{-# INLINE encrypt512 #-}
encrypt512 :: Key512 -> Tweak -> Block512 -> Block512
encrypt512 (Block512 k0 k1 k2 k3 k4 k5 k6 k7) (Tweak t0 t1) !input =
    case rounds 0 input of
      Block512 a b c d e f g h ->
        Block512 (a+k0) (b+k1) (c+k2) (d+k3)
                 (e+k4) (f+k5+t0) (g+k6+t1) (h+k7+18)
  where
    ks :: UArray Word64 Word64
    !ks = listArray (0, 8) [k0, k1, k2, k3, k4, k5, k6, k7, keyConst]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]
    
    rounds 18 input   = input
    rounds !n !input = rounds (n+1) (fourRounds input n (n*16))
    
    {-# INLINE fourRounds #-}
    fourRounds (Block512 a0 b0 c0 d0 e0 f0 g0 h0) keyOff r =
        Block512 a4 b4 c4 d4 e4 f4 g4 h4
      where
        {-# INLINE key #-}
        key n = ks ! ((keyOff + n) `rem` 9)
        {-# INLINE t #-}
        t n = ts ! ((keyOff + n) `rem` 3)
        (a1, b1) = mixKey a0 b0 (rot ! (r .&. 31)) (key 0) (key 1)
        (c1, d1) = mixKey c0 d0 (rot ! ((r+1) .&. 31)) (key 2) (key 3)
        (e1, f1) = mixKey e0 f0 (rot ! ((r+2) .&. 31)) (key 4) (key 5 + t 0)
        (g1, h1) = mixKey g0 h0 (rot ! ((r+3) .&. 31)) (key 6 + t 1) (key 7+keyOff)
        (c2, b2) = mix c1 b1 (rot ! ((r+4) .&. 31))
        (e2, h2) = mix e1 h1 (rot ! ((r+5) .&. 31))
        (g2, f2) = mix g1 f1 (rot ! ((r+6) .&. 31))
        (a2, d2) = mix a1 d1 (rot ! ((r+7) .&. 31))
        (e3, b3) = mix e2 b2 (rot ! ((r+8) .&. 31))
        (g3, d3) = mix g2 d2 (rot ! ((r+9) .&. 31))
        (a3, f3) = mix a2 f2 (rot ! ((r+10) .&. 31))
        (c3, h3) = mix c2 h2 (rot ! ((r+11) .&. 31))
        (g4, b4) = mix g3 b3 (rot ! ((r+12) .&. 31))
        (a4, h4) = mix a3 h3 (rot ! ((r+13) .&. 31))
        (c4, f4) = mix c3 f3 (rot ! ((r+14) .&. 31))
        (e4, d4) = mix e3 d3 (rot ! ((r+15) .&. 31))

-- | Encrypt a 512 bit Threefish block.
{-# INLINE decrypt512 #-}
decrypt512 :: Key512 -> Tweak -> Block512 -> Block512
decrypt512 (Block512 k0 k1 k2 k3 k4 k5 k6 k7) (Tweak t0 t1) !input =
    case input of
      (Block512 a b c d e f g h) ->
        rounds 18 $ Block512 (a-k0) (b-k1) (c-k2) (d-k3)
                            (e-k4) (f-(k5+t0)) (g-(k6+t1)) (h-(k7+18))
  where
    ks :: UArray Word64 Word64
    !ks = listArray (0, 8) [k0, k1, k2, k3, k4, k5, k6, k7, keyConst]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]
    
    rounds 0 input   = input
    rounds !n !input = rounds (n-1) (fourRounds input (n-1) ((n-1)*16))
    
    {-# INLINE fourRounds #-}
    fourRounds (Block512 a0 b0 c0 d0 e0 f0 g0 h0) keyOff r =
        Block512 a4 b4 c4 d4 e4 f4 g4 h4
      where
        {-# INLINE key #-}
        key n = ks ! ((keyOff + n) `rem` 9)
        {-# INLINE t #-}
        t n = ts ! ((keyOff + n) `rem` 3)
        (g1, b1) = unmix g0 b0 (rot ! ((r+12) .&. 31))
        (a1, h1) = unmix a0 h0 (rot ! ((r+13) .&. 31))
        (c1, f1) = unmix c0 f0 (rot ! ((r+14) .&. 31))
        (e1, d1) = unmix e0 d0 (rot ! ((r+15) .&. 31))
        (e2, b2) = unmix e1 b1 (rot ! ((r+8) .&. 31))
        (g2, d2) = unmix g1 d1 (rot ! ((r+9) .&. 31))
        (a2, f2) = unmix a1 f1 (rot ! ((r+10) .&. 31))
        (c2, h2) = unmix c1 h1 (rot ! ((r+11) .&. 31))
        (c3, b3) = unmix c2 b2 (rot ! ((r+4) .&. 31))
        (e3, h3) = unmix e2 h2 (rot ! ((r+5) .&. 31))
        (g3, f3) = unmix g2 f2 (rot ! ((r+6) .&. 31))
        (a3, d3) = unmix a2 d2 (rot ! ((r+7) .&. 31))
        (a4, b4) = unmixKey a3 b3 (rot ! (r .&. 31)) (key 0) (key 1)
        (c4, d4) = unmixKey c3 d3 (rot ! ((r+1) .&. 31)) (key 2) (key 3)
        (e4, f4) = unmixKey e3 f3 (rot ! ((r+2) .&. 31)) (key 4) (key 5 + t 0)
        (g4, h4) = unmixKey g3 h3 (rot ! ((r+3) .&. 31)) (key 6 + t 1) (key 7+keyOff)
