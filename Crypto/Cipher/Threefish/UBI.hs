-- | Tweak manipulation for Unique Block Iteration mode.
module Crypto.Cipher.Threefish.UBI where
import Data.Word
import Data.Bits
import Crypto.Cipher.Threefish.Common

data BlockType
  = Key
  | Config
  | Personalization
  | PublicKey
  | KeyIdentifier
  | Nonce
  | Message
  | Output

type2w64 :: BlockType -> Word64
type2w64 Key             = 0
type2w64 Config          = 4
type2w64 Personalization = 8
type2w64 PublicKey       = 12
type2w64 KeyIdentifier   = 16
type2w64 Nonce           = 20
type2w64 Message         = 48
type2w64 Output          = 63

{-# INLINE newTweak #-}
newTweak :: BlockType -> Tweak
newTweak t = setType t $ setFirst True $ Tweak 0 0

{-# INLINE setType #-}
setType :: BlockType -> Tweak -> Tweak
setType t (Tweak lo hi) =
    Tweak lo ((type2w64 t `shiftL` 56) .|. (hi .&. zeroType))
  where
    zeroType = complement (63 `shiftL` 56)

{-# INLINE setFirst #-}
setFirst :: Bool -> Tweak -> Tweak
setFirst set (Tweak lo hi) = Tweak lo ((if set then setBit else clearBit) hi 62)

{-# INLINE setLast #-}
setLast :: Bool -> Tweak -> Tweak
setLast set (Tweak lo hi) = Tweak lo ((if set then setBit else clearBit) hi 63)

{-# INLINE addBytes #-}
addBytes :: Word64 -> Tweak -> Tweak
addBytes bs (Tweak lo hi) = Tweak (lo + bs) hi

{-# INLINE configTweak #-}
configTweak :: Tweak
configTweak = setFirst True $ setLast True $ newTweak Config
