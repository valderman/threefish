-- | Skein as a key derivation function.
module Crypto.Threefish.Skein.KDF (deriveKey, deriveKeys) where
import Crypto.Threefish.Skein.Internal
import Crypto.Threefish.Skein
import Crypto.Threefish.UBI
import Crypto.Threefish.Threefish256
import Data.Serialize
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
import System.IO.Unsafe
import Foreign.Marshal.Alloc
import Foreign.Ptr

-- | Derive up to 2^64 keys from a master key.
--   The key identifiers will be 0, 1, ... 2^64-1.
deriveKeys :: Key256 -> [Key256]
deriveKeys mk =
  [deriveKey mk (Block256 $ runPut $ mapM_ putWord64le [kid,0,0,0]) |
   kid <- [0..]]

-- | Derive a key from a master key using a custom key identifier.
deriveKey :: Key256 -> Block256 -> Key256
deriveKey (Block256 mk) (Block256 kid) =
    unsafePerformIO $ do
      allocaBytes 64 $ \ctx -> do
        allocaBytes 32 $ \outkey -> do
          unsafeUseAsCString mk $ \masterkey -> do
            unsafeUseAsCString kid $ \keyid -> do
              skein256_init ctx (castPtr masterkey) 256
              skein256_update ctx 3 (type2int KeyIdentifier) l (castPtr keyid)
              skein256_output ctx 0 0 outkey
              Block256 `fmap` BS.packCStringLen (castPtr outkey, 32)
  where
    l = fromIntegral $ BS.length kid
