{-# LANGUAGE BangPatterns, OverloadedStrings, ForeignFunctionInterface #-}
-- | 256 and 512 bit Skein. Supports "normal" hashing and Skein-MAC.
module Crypto.Threefish.Skein (
    Skein (..), Block256 (..), Block512 (..), Key256, Key512,
    hash256, hash512
  ) where
import qualified Data.ByteString as BS
import Crypto.Threefish.Threefish256
import Crypto.Threefish.Threefish512
import Crypto.Threefish.UBI
import Data.Bits
import Data.Serialize
import Data.Word
import Data.ByteString.Unsafe
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe

foreign import ccall "hash256" c_hash256 :: Ptr Word64
                                         -> Word64
                                         -> Ptr Word64
                                         -> Int
                                         -> Ptr Word64
                                         -> IO ()

class Skein a where
  -- | Calculate the Skein-MAC of a message.
  skeinMAC :: a -> BS.ByteString -> a
  -- | Calculate the Skein checksum of a message.
  skein :: BS.ByteString -> a

-- | Hash a message using a particular key. For normal hashing, use an empty
--   ByteString; for Skein-MAC, use the MAC key.
hash256 :: Int -> Key256 -> BS.ByteString -> BS.ByteString
hash256 outlen (Block256 key) !msg = unsafePerformIO $ do
    unsafeUseAsCString key $ \k -> do
      unsafeUseAsCString msg $ \b -> do
        out <- mallocForeignPtrArray outwords
        withForeignPtr out $ \out' -> do
          c_hash256 (keyptr k) len (castPtr b) outlen out'
          BS.packCStringLen (castPtr out', outlen)
  where
    !outwords = outlen + case 32 - outlen `rem` 32 of 32 -> 0 ; pad -> pad
    !len = fromIntegral $ BS.length msg
    keyptr k | BS.length key == 32 = castPtr k
             | otherwise           = nullPtr

{-# INLINE skein256 #-}
-- | Hash a message using 256 bit Skein.
skein256 :: BS.ByteString -> Block256
skein256 = Block256 . hash256 32 (Block256 "")

{-# INLINE skeinMAC256 #-}
-- | Create a 256 bit Skein-MAC.
skeinMAC256 :: Key256 -> BS.ByteString -> Block256
skeinMAC256 key = Block256 . hash256 32 key

instance Skein Block256 where
  skeinMAC = skeinMAC256
  skein    = skein256



---------------------
-- 512 bit version --
---------------------

config512 :: Block512
config512 = Block512 0x0000000133414853 512 0 0 0 0 0 0

{-# INLINE xb512 #-}
xb512 :: Block512 -> Block512 -> Block512
xb512 (Block512 x1 x2 x3 x4 x5 x6 x7 x8)
      (Block512 y1 y2 y3 y4 y5 y6 y7 y8) =
  Block512 (x1 `xor` y1) (x2 `xor` y2) (x3 `xor` y3) (x4 `xor` y4)
           (x5 `xor` y5) (x6 `xor` y6) (x7 `xor` y7) (x8 `xor` y8)

-- | Initial state for Skein512
init512 :: Key512 -> Block512
init512 key = fst $ processBlock512 32 key configTweak config512

zero512 :: Block512
zero512 = Block512 0 0 0 0 0 0 0 0

{-# INLINE processBlock512 #-}
-- | Process a single block of Skein 512. Call on Threefish, XOR the cryptotext
--   with the plaintext and update the tweak.
processBlock512 :: Word64 -> Key512 -> Tweak -> Block512 -> (Key512, Tweak)
processBlock512 !len !key !tweak !block =
    (encrypt512 key tweak' block `xb512` block, setFirst False tweak')
  where
    !tweak' = addBytes len tweak

-- | Hash a message using a particular key. For normal hashing, use all zeroes;
--   for Skein-MAC, use the MAC key.
hash512 :: Key512 -> BS.ByteString -> Block512
hash512 !firstkey !bs =
    case flip runGet bs' $ go len (init512 firstkey) (newTweak Message) of
      Right x -> x
      Left _  -> error "hash512 failed to get output bytes - impossible!"
  where
    !len = BS.length bs
    !lastLen = case len `rem` 64 of 0 -> 64 ; n -> n
    !lastLenW64 = fromIntegral lastLen
    !bs' = BS.append bs (BS.replicate (64-lastLen) 0)
    go !n !key !tweak
      | n > 64 = do
        block <- get
        let (block', tweak') = processBlock512 64 key tweak block
        go (n-64) block' tweak'
      | otherwise = do
        block <- get
        let tweak' = setLast True tweak
            (block', _) = processBlock512 lastLenW64 key tweak' block
            finalTweak = setLast True $ newTweak Output
            (b,_) = processBlock512 8 block' finalTweak zero512
        return b

{-# INLINE skein512 #-}
-- | Hash a message using 512 bit Skein.
skein512 :: BS.ByteString -> Block512
skein512 = hash512 zero512

{-# INLINE skeinMAC512 #-}
-- | Create a 512 bit Skein-MAC.
skeinMAC512 :: Key512 -> BS.ByteString -> Block512
skeinMAC512 =
  hash512 . fst . processBlock512 64 zero512 (setLast True $ newTweak Key)

instance Skein Block512 where
  skeinMAC = skeinMAC512
  skein    = skein512
