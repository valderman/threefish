{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Crypto.Cipher.Threefish.Class where
import Crypto.Cipher.Threefish.Common

class Threefish a b | a -> b where
  -- | Create a Threefish key using a custom tweak value.
  threefishKey :: Tweak -> a -> b
  -- | Encrypt a block using the given key and tweak value.
  threefishEncrypt :: a -> Tweak -> a -> a
  -- | Decrypt a block using the given key and tweak value.
  threefishDecrypt :: a -> Tweak -> a -> a
