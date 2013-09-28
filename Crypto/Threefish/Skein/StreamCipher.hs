-- | 256 bit Skein as a stream cipher, as specified in the Skein 1.3 paper.
module Crypto.Threefish.Skein.StreamCipher (
    Key256, Nonce256, Block256 (..),
    encrypt, decrypt
  ) where
import Crypto.Threefish.Skein (Key256, Nonce256, Block256 (..))
import Crypto.Threefish.UBI
import Crypto.Threefish.Skein.Internal
import Data.ByteString.Unsafe
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Alloc
import System.IO.Unsafe
import Data.Bits (xor)

init256 :: Key256 -> Nonce256 -> Skein256Ctx
init256 (Block256 k) (Block256 n) =
    unsafePerformIO $ do
      c <- mallocForeignPtrBytes 64
      withForeignPtr c $ \ctx -> do
        unsafeUseAsCString k $ \key -> do
          unsafeUseAsCString n $ \nonce -> do
            skein256_init ctx (castPtr key) 0xffffffffffffffff
            skein256_update ctx 3 (type2int Nonce) len (castPtr nonce)
      return (Skein256Ctx c)
  where
    len = fromIntegral $ BS.length n

stream256 :: Skein256Ctx -> [BS.ByteString]
stream256 (Skein256Ctx c) =
    unsafePerformIO $ go 0
  where
    go n = unsafeInterleaveIO $ do
      bs <- withForeignPtr c $ \ctx -> do
        allocaBytes 256 $ \ptr -> do
          skein256_output ctx n (n+8) ptr
          BS.packCStringLen (castPtr ptr, 256)
      bss <- go (n+8)
      return $ bs : bss

keystream256 :: Key256 -> Nonce256 -> [BS.ByteString]
keystream256 k n = stream256 (init256 k n)

-- | Encrypt a lazy ByteString using 256 bit Skein as a stream cipher.
encrypt :: Key256 -> Nonce256 -> BSL.ByteString -> BSL.ByteString
encrypt k n plaintext =
    BSL.fromChunks $ go (keystream256 k n) plaintext
  where
    go (ks:kss) msg = unsafePerformIO . unsafeInterleaveIO $ do
      case BSL.splitAt 256 msg of
        (chunk, rest)
          | BSL.null rest ->
            return []
          | otherwise ->
            let chunk' = BSL.toStrict chunk
            in  return $ (BS.pack $ BS.zipWith xor ks chunk') : go kss rest

-- | Encryption and decryption are the same operation for a stream cipher, but
--   we may want to have a function called encrypt for clarity.
decrypt :: Key256 -> Nonce256 -> BSL.ByteString -> BSL.ByteString
decrypt = encrypt
