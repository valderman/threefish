{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
-- | 256 and 512 bit variants of the Threefish block cipher used as the
--   foundation of the Skein hash function.
module Crypto.Threefish (  
    Block256 (..), Threefish256, Key256,
    Block512 (..), Threefish512, Key512,
    Tweak (..), parseHex, readHex, defaultTweak,
    Threefish (..),
    Skein (..)
) where
import Crypto.Threefish.Threefish256 as TF256
import Crypto.Threefish.Threefish512 as TF512
import Crypto.Threefish.Common as Common
import Crypto.Threefish.Skein as Skein
import Data.Serialize

class Serialize a => Threefish a b | a -> b where
  -- | Create a Threefish key using a custom tweak value.
  threefishKey :: Tweak -> a -> b
  -- | Encrypt a block using the given key and tweak value.
  threefishEncrypt :: a -> Tweak -> a -> a
  -- | Decrypt a block using the given key and tweak value.
  threefishDecrypt :: a -> Tweak -> a -> a

instance Threefish Block256 Threefish256 where
  threefishKey = Threefish256
  threefishEncrypt = encrypt256
  threefishDecrypt = decrypt256

instance Threefish Block512 Threefish512 where
  threefishKey = Threefish512
  threefishEncrypt = encrypt512
  threefishDecrypt = decrypt512
