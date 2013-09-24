{-# LANGUAGE BangPatterns, ForeignFunctionInterface #-}
-- | 256 bit Threefish.
module Crypto.Cipher.Threefish.Threefish256 (
    Block256 (..), Key256, Threefish256 (..),
    encrypt256, decrypt256, readBlock256, Tweak (..)
  ) where
import Data.Word
import Data.Bits
import Crypto.Cipher.Threefish.Mix
import Crypto.Cipher.Threefish.Common
import Data.Serialize
import Control.Applicative
import Crypto.Classes
import Data.Tagged
import qualified Data.ByteString as BS
import Data.ByteString.Unsafe
import Foreign.Storable
import Foreign.Ptr
import Foreign.ForeignPtr
import System.IO.Unsafe

foreign import ccall "encrypt256" c_encrypt256 :: Ptr Word64
                                               -> Ptr Word64
                                               -> Ptr Word64
                                               -> Ptr Word64
                                               -> IO ()

foreign import ccall "decrypt256" c_decrypt256 :: Ptr Word64
                                               -> Ptr Word64
                                               -> Ptr Word64
                                               -> Ptr Word64
                                               -> IO ()

newtype Block256 = Block256 BS.ByteString deriving Eq
type Key256 = Block256

instance Show Block256 where
  show (Block256 bs) =
    case readBlock256 bs 0 of
      (a, b, c, d) -> showBytes a ++ showBytes b ++ showBytes c ++ showBytes d

instance Serialize Block256 where
  put (Block256 bs) = putByteString bs
  get = Block256 <$> getBytes 32

instance Serialize Threefish256 where
  put (Threefish256 tweak key) = put tweak >> put key
  get = Threefish256 <$> get <*> get

-- | 256 bit Threefish block cipher.
data Threefish256 = Threefish256 !Tweak !Key256

{-# INLINE readBlock256 #-}
readBlock256 :: BS.ByteString -> Int -> (Word64, Word64, Word64, Word64)
readBlock256 bs off = unsafePerformIO . unsafeUseAsCString bs $ \ptr -> do
  a <- peekElemOff (castPtr ptr) off
  b <- peekElemOff (castPtr ptr) (off+1)
  c <- peekElemOff (castPtr ptr) (off+2)
  d <- peekElemOff (castPtr ptr) (off+3)
  return $! (a, b, c, d)

instance BlockCipher Threefish256 where
  blockSize = Tagged 256
  keyLength = Tagged 256
  encryptBlock (Threefish256 tweak key) block =
    case encrypt256 key tweak (Block256 block) of
      Block256 out -> out
  decryptBlock (Threefish256 tweak key) block =
    case decrypt256 key tweak (Block256 block) of
      Block256 out -> out
  buildKey bs | BS.length bs /= 32 = Nothing
              | otherwise          = Just (Threefish256 defaultTweak
                                                        (Block256 bs))

decrypt256 :: Key256 -> Tweak -> Block256 -> Block256
decrypt256 (Block256 key) (Tweak t0 t1) (Block256 block) =
  unsafePerformIO $ unsafeUseAsCString key $ \k ->
                    unsafeUseAsCString block $ \b -> do
                      t <- mallocForeignPtrArray 2
                      out <- mallocForeignPtrArray 4
                      withForeignPtr t $ \t' -> do
                        pokeElemOff t' 0 t0
                        pokeElemOff t' 1 t1
                        withForeignPtr out $ \out' -> do
                          c_decrypt256 (castPtr k) t' (castPtr b) out'
                          Block256 <$> BS.packCStringLen (castPtr out', 32)

encrypt256 :: Key256 -> Tweak -> Block256 -> Block256
encrypt256 (Block256 key) (Tweak t0 t1) (Block256 block) =
  unsafePerformIO $ unsafeUseAsCString key $ \k ->
                    unsafeUseAsCString block $ \b -> do
                      t <- mallocForeignPtrArray 2
                      out <- mallocForeignPtrArray 4
                      withForeignPtr t $ \t' -> do
                        pokeElemOff t' 0 t0
                        pokeElemOff t' 1 t1
                        withForeignPtr out $ \out' -> do
                          c_encrypt256 (castPtr k) t' (castPtr b) out'
                          Block256 <$> BS.packCStringLen (castPtr out', 32)
