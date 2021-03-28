{-# LANGUAGE NoImplicitPrelude #-}

module Crypto.ECC.Signify ( parsePubKey
                          , parseSignature
                          , parseSecKey
                          , printPubKey
                          , printSignature
                          , printSecKey
                          ) where

import Text.Parsec
import Data.Either (Either(..))
import Data.String (String)
import Data.Function (($))
import Data.List ((++),drop,map)
import Data.Eq ((==),(/=))
import Data.Bool ((&&))
import Text.Show (show)
import Control.Monad
import qualified Data.ByteString as B
import Data.ByteString.Internal (c2w)
import Data.ByteString.Base64
import Crypto.ECC.Ed25519.Sign
import qualified Crypto.ECC.Ed25519.Internal.Ed25519 as DANGER
import Crypto.KDF.BCryptPBKDF
import Data.Bits
import qualified Crypto.Hash.SHA512 as H

type KeyID = B.ByteString
type Comment = String
type FileContent = B.ByteString
type Passphrase = B.ByteString
type Errormsg = String
type Salt = B.ByteString

parsePubKey :: FileContent -> Either Errormsg (Comment, KeyID, PubKey)
parsePubKey = parsePubOrSig

parseSignature :: FileContent -> Either Errormsg (Comment, KeyID, Signature)
parseSignature = parsePubOrSig

parseSecKey :: Passphrase -> FileContent -> Either Errormsg (Comment, KeyID, SecKey)
parseSecKey pass file = do
  (comment, rest) <- parseSignifyFileContent file
  let (kdfalg,rest2) = B.splitAt 2 rest
      (kdfrounds,rest3) = B.splitAt 4 rest2
      (salt,rest4) = B.splitAt 16 rest3
      (cksum,rest5) = B.splitAt 8 rest4
      (keyid,encbytes) = B.splitAt 8 rest5
--      rounds = fromBytes $ B.reverse kdfrounds
      rounds = 42 -- magic number, TODO: get rid of
      params = Parameters {iterCounts = rounds, outputLength = B.length encbytes}
      hashpw = generate params pass salt
      secbytes = B.pack $ B.zipWith xor encbytes hashpw
      resultbytes = if pass == B.empty then encbytes else secbytes
  if B.take 8 (H.hash resultbytes) == cksum
    then return (comment, keyid, DANGER.SecKeyBytes resultbytes)
    else Left "signify-hs: incorrect passphrase"

printPubKey :: KeyID -> PubKey -> Comment -> FileContent
printPubKey keyID pubKey comment = B.pack (map c2w ("untrusted comment: " ++ comment ++ " public key")) `B.append`
                                   B.pack (map c2w "\n") `B.append`
                                   encode (
                                     B.pack (map c2w "Ed") `B.append` -- signify file format magic
                                     keyID `B.append`
                                     pubKey
                                   ) `B.append`
                                   B.pack (map c2w "\n")

printSignature :: KeyID -> Signature -> Comment -> FileContent
printSignature keyID sig comment = B.pack (map c2w ("untrusted comment: " ++ comment)) `B.append`
                                   B.pack (map c2w "\n") `B.append`
                                   encode (
                                     B.pack (map c2w "Ed") `B.append` -- signify file format magic
                                     keyID `B.append`
                                     sig
                                   ) `B.append`
                                   B.pack (map c2w "\n")

printSecKey :: KeyID -> Passphrase -> Salt -> SecKey -> PubKey -> Comment -> FileContent
printSecKey keyID passphrase salt (DANGER.SecKeyBytes secKeyBytes) pubKeyBytes comment =
  let rounds = 42
      longkey = secKeyBytes `B.append` pubKeyBytes
      params = Parameters {iterCounts = rounds, outputLength = B.length longkey}
      hashpw = generate params passphrase salt
      secdata = B.pack $ B.zipWith xor longkey hashpw
      cksum = B.take 8 $ H.hash longkey
      fulldata = B.pack (map c2w "Ed") `B.append` -- signify file format magic
                 B.pack (map c2w "BK") `B.append` -- signify file format magic
                 B.pack (map c2w (if passphrase /= B.empty then "\NUL\NUL\NUL*" else "\NUL\NUL\NUL\NUL")) `B.append` -- manually hack rounds magic number 42 for now, TODO cleanly
                 salt `B.append`
                 cksum `B.append`
                 keyID `B.append`
                 (if passphrase /= B.empty then secdata else longkey)
  in B.pack (map c2w ("untrusted comment: " ++ comment ++ " secret key")) `B.append`
     B.pack (map c2w "\n") `B.append`
     encode fulldata `B.append`
     B.pack (map c2w "\n")

{-
-- Read bytes in big-endian order (most significant byte first)
-- Little-endian order is fromBytes . BS.reverse
fromBytes :: (Bits a, Num a) => B.ByteString -> a
fromBytes = B.foldl' f 0
  where
    f a b = a `shiftL` 8 .|. fromIntegral b

toBytes :: (Bits a, Num a) => a -> B.ByteString
toBytes = undefined
-- -}

parsePubOrSig :: FileContent -> Either Errormsg (Comment, KeyID, B.ByteString)
parsePubOrSig file = do
  (comment, rest) <- parseSignifyFileContent file
  let (keyid, signifydata) = B.splitAt 8 rest
  return (comment, keyid, signifydata)

parseSignifyFileContent :: FileContent -> Either Errormsg (Comment, B.ByteString)
parseSignifyFileContent file = do
  let res = parse signifyFile "(unknown)" file
  case res of
    Left s -> Left $ show s
    Right (comment,bytes) -> do
      let (alg,rest) = B.splitAt 2 bytes
      if alg /= B.pack (map c2w "Ed") && alg /= B.pack (map c2w "ED")
        then Left "currently unsupported signing algorithm"
        else return (drop 19 comment, rest)

signifyFile :: Parsec FileContent u (Comment, B.ByteString)
signifyFile = do
  comment <- many (noneOf "\r\n")
  _ <- endOfLine
  base64data <- many (noneOf "\r\n")
  _ <- endOfLine
  let base64decoded = decode $ B.pack $ map c2w base64data
  case base64decoded of
    Left s -> parserFail s
    Right dat -> return (comment,dat)
