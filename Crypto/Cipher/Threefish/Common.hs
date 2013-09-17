-- | Misc. shared constants and functions.
module Crypto.Cipher.Threefish.Common (Tweak (..), showBytes, keyConst) where
import Numeric (showHex)
import Data.Word
import Data.Bits

-- | Show a little endian Word64 as a string of bytes.
showBytes :: Word64 -> String
showBytes =
    go 8
  where
    sr = shiftR
    go 0 _ = ""
    go n w = showHex ((w`sr`4).&.15) $ showHex (w.&.15) $ go (n-1) (w`sr`8)

-- | Key constant for Threefish.
keyConst :: Word64
keyConst = 0x1BD11BDAA9FC1A22

-- | Threefish tweak value. Please see the Skein specification for info on
--   how to use this.
data Tweak = Tweak {-# UNPACK #-} !Word64
                   {-# UNPACK #-} !Word64
