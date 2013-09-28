-- | Skein 256 as a PRNG.
module Crypto.Threefish.Random (
    SkeinGen, Block256, Random (..), RandomGen (..),
    newSkeinGen, mkSkeinGen, mkSkeinGenEx, randomBytes, reseedSkeinGen,
    toBlock, fromBlock
  ) where
import Crypto.Threefish.Skein
import Crypto.Threefish.Threefish256
import System.Random
import System.Entropy
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.ByteString.Unsafe
import System.IO.Unsafe
import Foreign.Storable (sizeOf, peek)
import Foreign.Ptr (castPtr)
import Data.Serialize
import Crypto.Random
import Data.Tagged

emptyKey :: Key256
emptyKey = Block256 BS.empty

-- | Default amount of random bytes to buffer.
defaultSkeinGenPoolSize :: Int
defaultSkeinGenPoolSize = 256

-- | Skein-based PRNG as defined in the Skein 1.3 paper.
data SkeinGen = SkeinGen {
    sgState    :: Block256,
    sgPool     :: BS.ByteString,
    sgPoolSize :: Int
  }

instance RandomGen SkeinGen where
  next g =
    case randomBytes (sizeOf (0::Int)) g of
      (bs, g') -> (unsafePerformIO $ unsafeUseAsCString bs $ peek . castPtr, g')
  split g =
    case BS.splitAt 32 (fst $ randomBytes 64 g) of
      (a, b) -> (mkSkeinGenEx (sgPoolSize g) (Block256 a),
                 mkSkeinGenEx (sgPoolSize g) (Block256 b))

-- | Create a new Skein PRNG from the system's entropy pool.
newSkeinGen :: IO SkeinGen
newSkeinGen =
  (mkSkeinGenEx defaultSkeinGenPoolSize . Block256) `fmap` getEntropy 32

-- | Create a Skein PRNG from a seed.
mkSkeinGen :: Serialize a => a -> SkeinGen
mkSkeinGen = mkSkeinGenEx defaultSkeinGenPoolSize . Block256 . encode

-- | Create a Skein PRNG with a custom pool size. Larger pool sizes give faster
--   random data, but obviously take up more memory. Pool size is preserved
--   across splits.
mkSkeinGenEx :: Int -> Block256 -> SkeinGen
mkSkeinGenEx poolsize (Block256 seed) = SkeinGen {
    sgState    = skein $ BSL.fromStrict (BS.replicate 32 0 `BS.append` seed),
    sgPool     = BS.empty,
    sgPoolSize = poolsize
  }

-- | Reseed a Skein PRNG.
reseedSkeinGen :: Block256 -> SkeinGen -> SkeinGen
reseedSkeinGen (Block256 seed) (SkeinGen (Block256 state) _ poolsize) =
  SkeinGen {
    sgState    = skein $ BSL.fromStrict (state `BS.append` seed),
    sgPool     = BS.empty,
    sgPoolSize = poolsize
  }

-- | Generate n random bytes using the given generator.
randomBytes :: Int -> SkeinGen -> (BS.ByteString, SkeinGen)
randomBytes nbytes (SkeinGen (Block256 state) pool poolsize)
  | BS.length pool >= nbytes =
    case BS.splitAt nbytes pool of
      (output, rest) -> (output, SkeinGen (Block256 state) rest poolsize)
  | otherwise =
      (BS.append pool out, SkeinGen (Block256 state') pool' poolsize)
  where
    -- Use all of the output to avoid making unnecessary calls
    nbytes' = fromIntegral $ 32 + max (nbytes + (32-(nbytes`rem`32))) poolsize
    bytes = hash256 nbytes' emptyKey (BSL.fromStrict state)
    (state', buffer) = BS.splitAt 32 bytes
    (out, pool') = BS.splitAt (nbytes - BS.length pool) buffer

instance CryptoRandomGen SkeinGen where
  newGen seed =
    case BS.length seed of
      n | n >= 32 ->
          Right $ mkSkeinGenEx ps (Block256 $ BS.take 32 seed)
        | otherwise ->
          Left NotEnoughEntropy
    where ps = defaultSkeinGenPoolSize
  genSeedLength = Tagged 32
  genBytes n g =Right $ randomBytes n g
  reseedInfo = const Never
  reseedPeriod = const Never
  reseed seed g =
    case BS.length seed of
      n | n >= 32 ->
          Right $ reseedSkeinGen (Block256 $ BS.take 32 seed) g
        | otherwise ->
          Left NotEnoughEntropy
