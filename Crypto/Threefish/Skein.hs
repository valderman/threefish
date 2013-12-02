{-# LANGUAGE BangPatterns, OverloadedStrings, MultiParamTypeClasses #-}
-- | 256 and 512 bit Skein. Supports "normal" hashing and Skein-MAC.
module Crypto.Threefish.Skein (
    Skein (..), Threefish (..), Block256, Block512, Key256, Key512, Nonce256,
    hash256, hash512
  ) where
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Crypto.Threefish.Threefish256
import Crypto.Threefish.Threefish512
import Crypto.Threefish.UBI
import Crypto.Threefish
import Crypto.Threefish.Skein.Internal
import Data.Bits
import Data.Serialize
import Data.Word
import Data.ByteString.Unsafe
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import System.IO.Unsafe

class Skein a where
  -- | Calculate the Skein-MAC of a message.
  skeinMAC :: a -> BSL.ByteString -> a
  -- | Calculate the Skein checksum of a message.
  skein :: BSL.ByteString -> a

type Nonce256 = Block256

init256 :: Key256 -> Word64 -> Skein256Ctx
init256 (Block256 k) outlen =
    unsafePerformIO $ do
      c <- mallocForeignPtrBytes 64
      withForeignPtr c $ \ctx -> do
        withKey $ \key -> do
          skein256_init ctx (castPtr key) (outlen*8)
      return (Skein256Ctx c)
  where
    withKey f | BS.length k == 32 = unsafeUseAsCString k (f . castPtr)
              | otherwise         = f nullPtr

update256 :: Skein256Ctx -> Int -> BSL.ByteString -> BS.ByteString
update256 (Skein256Ctx c) outlen bytes =
    unsafePerformIO $ withForeignPtr c $ go 1 bytes
  where
    outblocks =
      case outlen `quotRem` 32 of
        (blocks, 0) -> blocks
        (blocks, _) -> blocks+1
    !msgtype = type2int Message
    go !first !msg !ctx = do
      case BSL.splitAt 16384 msg of
        (chunk, rest)
          | BSL.null chunk ->
            allocaBytes (outblocks*32) $ \ptr -> do
              skein256_output ctx 0 (outblocks-1) ptr
              BS.packCStringLen (castPtr ptr, outlen)
          | otherwise -> do
              let !chunk' =
                    toStrict chunk
                  (!lst, !len) =
                    if BSL.null rest
                      then (2, fromIntegral $ BS.length chunk')
                      else (0, 16384)
              unsafeUseAsCString chunk' $ \ptr -> do
                skein256_update ctx (first .|. lst) msgtype len (castPtr ptr)
              go 0 rest ctx

toStrict :: BSL.ByteString -> BS.ByteString
toStrict = BS.concat . BSL.toChunks

hash256 :: Word64 -> Key256 -> BSL.ByteString -> BS.ByteString
hash256 outlen k bs =
    case init256 k outlen of
      ctx -> update256 ctx (fromIntegral outlen) bs

{-# INLINE skein256 #-}
-- | Hash a message using 256 bit Skein.
skein256 :: BSL.ByteString -> Block256
skein256 = Block256 . hash256 32 (Block256 "")

{-# INLINE skeinMAC256 #-}
-- | Create a 256 bit Skein-MAC.
skeinMAC256 :: Key256 -> BSL.ByteString -> Block256
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
hash512 :: Key512 -> BSL.ByteString -> Block512
hash512 !firstkey !bs =
    case flip runGetLazy bs' $ go len (init512 firstkey) (newTweak Message) of
      Right x -> x
      Left _  -> error "hash512 failed to get output bytes - impossible!"
  where
    !len = BSL.length bs
    !lastLen = case len `rem` 64 of 0 -> 64 ; n -> n
    !lastLenW64 = fromIntegral lastLen
    !bs' = BSL.append bs (BSL.replicate (64-fromIntegral lastLen) 0)
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
skein512 :: BSL.ByteString -> Block512
skein512 = hash512 zero512

{-# INLINE skeinMAC512 #-}
-- | Create a 512 bit Skein-MAC.
skeinMAC512 :: Key512 -> BSL.ByteString -> Block512
skeinMAC512 =
  hash512 . fst . processBlock512 64 zero512 (setLast True $ newTweak Key)

instance Skein Block512 where
  skeinMAC = skeinMAC512
  skein    = skein512
