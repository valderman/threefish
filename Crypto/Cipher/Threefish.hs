{-# LANGUAGE MultiParamTypeClasses #-}
-- | 256 and 512 bit variants of the Threefish block cipher used as the
--   foundation of the Skein hash function.
module Crypto.Cipher.Threefish (  
    Block256 (..), Threefish256, Key256,
    Block512 (..), Threefish512, Key512,
    Tweak (..), parseHex, readHex, defaultTweak,
    Threefish (..)
) where
import Crypto.Cipher.Threefish.Threefish256 as TF256
import Crypto.Cipher.Threefish.Threefish512 as TF512
import Crypto.Cipher.Threefish.Common as Common
import Crypto.Cipher.Threefish.Class as Class

instance Threefish Block256 Threefish256 where
  threefishKey = Threefish256
  threefishEncrypt = encrypt256
  threefishDecrypt = decrypt256

instance Threefish Block512 Threefish512 where
  threefishKey = Threefish512
  threefishEncrypt = encrypt512
  threefishDecrypt = decrypt512
