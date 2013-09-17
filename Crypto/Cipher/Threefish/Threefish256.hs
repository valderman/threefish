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
data Threefish256 = Threefish256 Tweak Key256

-- | Rotational constants for TF256
rot :: UArray Word64 Int
rot = listArray (0,15) [14,16,52,57,23,40,5,37,25,33,46,12,58,22,32,32]

-- | Encrypt a 256 bit Threefish block. Tweak may have any value without
--   compromising security.
{-# INLINE encrypt256 #-}
encrypt256 :: Key256 -> Tweak -> Block256 -> Block256
encrypt256 (Block256 k0 k1 k2 k3) (Tweak t0 t1) !input =
    case rounds 0 input of
      Block256 a b c d -> Block256 (a+k3) (b+keyConst+t0) (c+k0+t1) (d+k1+18)
  where
    ks :: UArray Word64 Word64
    !ks = listArray (0, 4) [k0, k1, k2, k3, keyConst]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]
    
    rounds 18 input=
        input
    rounds !n !input =
        rounds (n+1) (fourRounds input (ks ! (n `rem` 5)) x y z (n*8))
      where
        x = (ks ! ((n+1) `rem` 5)) + (ts ! (n `rem` 3))
        y = (ks ! ((n+2) `rem` 5)) + (ts ! ((n+1) `rem` 3))
        z = (ks ! ((n+3) `rem` 5)) + n
    
    {-# INLINE fourRounds #-}
    fourRounds (Block256 a0 b0 c0 d0) key0 key1 key2 key3 r =
        Block256 a4 b4 c4 d4
      where
        (a1, b1) = mixKey a0 b0 (rot ! (r .&. 15)) key0 key1
        (c1, d1) = mixKey c0 d0 (rot ! ((r+1) .&. 15)) key2 key3
        (a2, d2) = mix a1 d1 (rot ! ((r+2) .&. 15))
        (c2, b2) = mix c1 b1 (rot ! ((r+3) .&. 15))
        (a3, b3) = mix a2 b2 (rot ! ((r+4) .&. 15))
        (c3, d3) = mix c2 d2 (rot ! ((r+5) .&. 15))
        (a4, d4) = mix a3 d3 (rot ! ((r+6) .&. 15))
        (c4, b4) = mix c3 b3 (rot ! ((r+7) .&. 15))

-- | Decrypt a 256 bit Threefish block.
{-# INLINE decrypt256 #-}
decrypt256 :: Key256 -> Tweak -> Block256 -> Block256
decrypt256 (Block256 k0 k1 k2 k3) (Tweak t0 t1) (Block256 a b c d) =
    rounds 18 (Block256 (a-k3) (b-(keyConst+t0)) (c-(k0+t1)) (d-(k1+18)))
  where
    ks :: UArray Word64 Word64
    !ks = listArray (0, 4) [k0, k1, k2, k3, keyConst]
    ts :: UArray Word64 Word64
    !ts = listArray (0, 2) [t0, t1, t0 `xor` t1]
    
    rounds 0 input=
      input
    rounds !n !input =
        rounds (n-1) (fourRounds input (ks ! ((n-1) `rem` 5)) x y z ((n-1)*8))
      where
        x = (ks ! (n `rem` 5)) + (ts ! ((n-1) `rem` 3))
        y = (ks ! ((n+1) `rem` 5)) + (ts ! (n `rem` 3))
        z = (ks ! ((n+2) `rem` 5)) + (n-1)
    
    {-# INLINE fourRounds #-}
    fourRounds (Block256 a0 b0 c0 d0) key0 key1 key2 key3 r =
        Block256 a4 b4 c4 d4
      where
        (a1, d1) = unmix a0 d0 (rot ! ((r+6) .&. 15))
        (c1, b1) = unmix c0 b0 (rot ! ((r+7) .&. 15))
        (a2, b2) = unmix a1 b1 (rot ! ((r+4) .&. 15))
        (c2, d2) = unmix c1 d1 (rot ! ((r+5) .&. 15))
        (a3, d3) = unmix a2 d2 (rot ! ((r+2) .&. 15))
        (c3, b3) = unmix c2 b2 (rot ! ((r+3) .&. 15))
        (a4, b4) = unmixKey a3 b3 (rot ! (r .&. 15)) key0 key1
        (c4, d4) = unmixKey c3 d3 (rot ! ((r+1) .&. 15)) key2 key3

instance BlockCipher Threefish256 where
  blockSize = Tagged 256
  keyLength = Tagged 256
  encryptBlock (Threefish256 tweak key) block =
    case decode block of
      Right block' -> encode (encrypt256 key tweak block')
      Left e       -> error $ "Not a valid Threefish512 block: " ++ show e
  decryptBlock (Threefish256 tweak key) block =
    case decode block of
      Right block' -> encode (decrypt256 key tweak block')
      Left e       -> error $ "Not a valid Threefish512 block: " ++ show e
  buildKey bs | BS.length bs /= 32 = Nothing
              | otherwise          = e2m (decode bs)
