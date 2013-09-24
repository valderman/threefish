-- | Misc. shared constants and functions.
module Crypto.Cipher.Threefish.Common (
    Tweak (..), showBytes, keyConst, e2m, defaultTweak, parseHex, readHex
  ) where
import Numeric (showHex)
import Data.Word
import Data.Bits
import Data.Serialize
import Control.Applicative
import qualified Data.ByteString as BS
import Data.Char
import Data.Default

hexDigit :: Char -> Maybe Word8
hexDigit c | c >= '0' && c <= '9' = Just $ fromIntegral $ ord c - ord '0'
           | c >= 'a' && c <= 'f' = Just $ fromIntegral $ ord c - ord 'a' + 10
           | c >= 'A' && c <= 'F' = Just $ fromIntegral $ ord c - ord 'A' + 10
           | otherwise            = Nothing

-- | Parses a string of hexadecimal digits into a ByteString.
parseHex :: String -> Maybe BS.ByteString
parseHex = go []
  where
    go :: [Word8] -> String -> Maybe BS.ByteString
    go bytes (h:l:xs) = do
      h' <- hexDigit h
      l' <- hexDigit l
      go (((h' `shiftL` 4) .|. l') : bytes) xs
    go bytes [] =
      Just (BS.pack (reverse bytes))
    go _ _ =
      Nothing

-- | Show a little endian Word64 as a string of bytes.
showBytes :: Word64 -> String
showBytes =
    go (8 :: Int)
  where
    sr = shiftR
    go 0 _ = ""
    go n w = showHex ((w`sr`4).&.15) $ showHex (w.&.15) $ go (n-1) (w`sr`8)

-- | Key constant for Threefish.
keyConst :: Word64
keyConst = 0x1BD11BDAA9FC1A22

-- | Default tweak when Threefish is used in CBC, CTR, etc. modes.
defaultTweak :: Tweak
defaultTweak = Tweak 0 0

-- | Turn an Either computation into its Maybe counterpart.
e2m :: Either a b -> Maybe b
e2m (Right x) = Just x
e2m _         = Nothing

-- | Threefish tweak value. Please see the Skein specification for info on
--   how to use this.
data Tweak = Tweak {-# UNPACK #-} !Word64
                   {-# UNPACK #-} !Word64

instance Serialize Tweak where
  put (Tweak low high) = putWord64le low >> putWord64le high
  get = Tweak <$> getWord64le <*> getWord64le

instance Show Tweak where
  show (Tweak low high) = showBytes low ++ showBytes high

instance Default Tweak where
  def = defaultTweak

-- | Read any deserializable type from a hex string.
readHex :: Serialize a => String -> Maybe a
readHex s = parseHex s >>= e2m . decode
