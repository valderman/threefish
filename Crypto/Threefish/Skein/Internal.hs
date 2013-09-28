{-# LANGUAGE ForeignFunctionInterface #-}
-- | Skein FFI internals.
module Crypto.Threefish.Skein.Internal where
import Foreign.ForeignPtr
import Foreign.Ptr
import Data.Word
       
newtype Skein256Ctx = Skein256Ctx (ForeignPtr Word64)

foreign import ccall unsafe skein256_init
  :: Ptr Word64 -- ^ Skein 256 context to initialize.
  -> Ptr Word64 -- ^ Desired key or nullPtr.
  -> Word64     -- ^ Output size in bits.
  -> IO ()

foreign import ccall unsafe skein256_update
  :: Ptr Word64 -- ^ Skein 256 context.
  -> Int        -- ^ First/last update? First starts a new tweak.
                --  (First bit indicates first, second bit indicates last.)
  -> Int        -- ^ Type of block, as given by type2int.
  -> Word64     -- ^ Length of block. Must be multiple of 32 except for last.
  -> Ptr Word64 -- ^ Pointer to update data.
  -> IO ()

foreign import ccall unsafe skein256_output
  :: Ptr Word64 -- ^ Skein 256 context.
  -> Int        -- ^ First output block to get.
  -> Int        -- ^ Last output block to get.
  -> Ptr Word64 -- ^ Pointer to store output data in.
  -> IO ()
