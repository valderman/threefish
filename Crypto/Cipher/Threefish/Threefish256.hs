{-# LANGUAGE BangPatterns #-}
-- | 256 bit Threefish.
module Crypto.Cipher.Threefish.Threefish256 where
import Data.Word
import Data.Bits
import Crypto.Cipher.Threefish.Mix
import Crypto.Cipher.Threefish.Common
import Data.Array.Unboxed
import Data.Serialize
import Control.Applicative
import Crypto.Classes
import Data.Tagged
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
import Foreign.Storable
import Foreign.Ptr
import System.IO.Unsafe

data Block256 = Block256 {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                         {-# UNPACK #-} !Word64
                deriving Eq

type Key256 = Block256

instance Show Block256 where
  show (Block256 a b c d) =
    showBytes a ++ showBytes b ++ showBytes c ++ showBytes d

instance Serialize Block256 where
  put (Block256 a b c d) =
    putWord64le a >> putWord64le b >> putWord64le c >> putWord64le d
  get =
    Block256 <$> getWord64le <*> getWord64le <*> getWord64le <*> getWord64le

instance Serialize Threefish256 where
  put (Threefish256 tweak key) = put tweak >> put key
  get = Threefish256 <$> get <*> get

-- | 256 bit Threefish block cipher.
data Threefish256 = Threefish256 !Tweak !Key256

-- | Encrypt a 256 bit Threefish block. Tweak may have any value without
--   compromising security.
{-# INLINE encrypt256 #-}
encrypt256 :: Key256 -> Tweak -> Block256 -> Block256
encrypt256 (Block256 k0 k1 k2 k3) (Tweak t0 t1) (Block256 a b c d) =
    rounds 1 (Block256 (a+k0) (b+k1+t0) (c+k2+t1) (d+k3))
  where
    !k4 = keyConst`xor`k0`xor`k1`xor`k2`xor`k3
    ks :: UArray Word64 Word64
    !ks = listArray (0, 4) [k0, k1, k2, k3, k4]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]

    rounds 10 input  = input
    rounds !n !input = rounds (n+1) (eightRounds input n)

    {-# INLINE injectKey #-}
    injectKey !a !b !c !d !r =
      (a + (ks ! (r`rem`5)),
       b + (ks ! ((r+1) `rem` 5)) + (ts ! (r `rem` 3)),
       c + (ks ! ((r+2) `rem` 5)) + (ts ! ((r+1) `rem` 3)),
       d + (ks ! ((r+3) `rem` 5)) + r)

    {-# INLINE eightRounds #-}
    eightRounds (Block256 a0 b0 c0 d0) !r =
        Block256 a'' b'' c'' d''
      where
        (!a1, !b1) = mix a0 b0 14
        (!c1, !d1) = mix c0 d0 16
        (!a2, !d2) = mix a1 d1 52
        (!c2, !b2) = mix c1 b1 57
        (!a3, !b3) = mix a2 b2 23
        (!c3, !d3) = mix c2 d2 40
        (!a4, !d4) = mix a3 d3 5
        (!c4, !b4) = mix c3 b3 37
        (!a',!b',!c',!d') = injectKey a4 b4 c4 d4 (2*r-1)
        (!a5, !b5) = mix a' b' 25
        (!c5, !d5) = mix c' d' 33
        (!a6, !d6) = mix a5 d5 46
        (!c6, !b6) = mix c5 b5 12
        (!a7, !b7) = mix a6 b6 58
        (!c7, !d7) = mix c6 d6 22
        (!a8, !d8) = mix a7 d7 32
        (!c8, !b8) = mix c7 b7 32
        (!a'',!b'',!c'',!d'') = injectKey a8 b8 c8 d8 (2*r)

-- | Encrypt a 256 bit Threefish block. Tweak may have any value without
--   compromising security.
{-# INLINE decrypt256 #-}
decrypt256 :: Key256 -> Tweak -> Block256 -> Block256
decrypt256 (Block256 k0 k1 k2 k3) (Tweak t0 t1) !input =
    case rounds 1 input of 
      (Block256 a b c d) -> Block256 (a-k0) (b-(k1+t0)) (c-(k2+t1)) (d-k3)
  where
    k4 = keyConst`xor`k0`xor`k1`xor`k2`xor`k3
    ks :: UArray Word64 Word64
    !ks = listArray (0, 4) [k0, k1, k2, k3, k4]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]

    rounds 10 input  = input
    rounds !n !input = rounds (n+1) (eightRounds input (10-n))

    {-# INLINE injectKey #-}
    injectKey a b c d r = (a - (ks ! (r`rem`5)),
                           b - ((ks ! ((r+1) `rem` 5)) + (ts ! (r `rem` 3))),
                           c - ((ks ! ((r+2) `rem` 5)) + (ts ! ((r+1) `rem` 3))),
                           d - ((ks ! ((r+3) `rem` 5)) + r))

    {-# INLINE eightRounds #-}
    eightRounds (Block256 a b c d) !r =
        Block256 a8 b8 c8 d8
      where
        (!a0,!b0,!c0,!d0) = injectKey a b c d (2*r)
        (!a1, !d1) = unmix a0 d0 32
        (!c1, !b1) = unmix c0 b0 32
        (!a2, !b2) = unmix a1 b1 58
        (!c2, !d2) = unmix c1 d1 22
        (!a3, !d3) = unmix a2 d2 46
        (!c3, !b3) = unmix c2 b2 12
        (!a4, !b4) = unmix a3 b3 25
        (!c4, !d4) = unmix c3 d3 33
        (!a',!b',!c',!d') = injectKey a4 b4 c4 d4 (2*r-1)
        (!a5, !d5) = unmix a' d' 5
        (!c5, !b5) = unmix c' b' 37
        (!a6, !b6) = unmix a5 b5 23
        (!c6, !d6) = unmix c5 d5 40
        (!a7, !d7) = unmix a6 d6 52
        (!c7, !b7) = unmix c6 b6 57
        (!a8, !b8) = unmix a7 b7 14
        (!c8, !d8) = unmix c7 d7 16

{-# INLINE readBlock256 #-}
readBlock256 :: Ptr Word64 -> Int -> IO Block256
readBlock256 ptr off = do
  a <- peekElemOff ptr off
  b <- peekElemOff ptr (off+1)
  c <- peekElemOff ptr (off+2)
  d <- peekElemOff ptr (off+3)
  return $! Block256 a b c d

instance BlockCipher Threefish256 where
  blockSize = Tagged 256
  keyLength = Tagged 256
  encryptBlock (Threefish256 tweak key) block =
    unsafePerformIO . unsafeUseAsCString block $ \ptr -> do
      block' <- readBlock256 (castPtr ptr) 0
      return $! encode $! encrypt256 key tweak block'
  decryptBlock (Threefish256 tweak key) block =
    unsafePerformIO . unsafeUseAsCString block $ \ptr -> do
      block' <- readBlock256 (castPtr ptr) 0
      return $! encode $! decrypt256 key tweak block'
  buildKey bs | BS.length bs /= 32 = Nothing
              | otherwise          = e2m (decode bs)
