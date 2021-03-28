{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Main where

import Options.Applicative as O
import Data.Maybe (fromMaybe,isNothing,Maybe(..))
import Data.Either (Either(..))
import Data.Bool (Bool(..),(||),otherwise)
import Data.String (String)
import Data.List ((++),drop)
import Data.Eq ((==))
import Data.Function (($))
import Crypto.ECC.Signify
import qualified Crypto.ECC.Ed25519.Sign as Ed
import qualified Data.ByteString as B
import Control.Monad
import Data.Semigroup ((<>))
import System.Exit
import System.Environment (getProgName)
import System.FilePath (takeBaseName)
import System.IO (hSetEcho,stdin,stdout,hFlush,IO(),FilePath,putStrLn,putStr,print)
-- import System.FileArchive.GZip

#ifndef mingw32_HOST_OS
import qualified Data.ByteString.Lazy.Char8 as BS8
#else
import qualified Crypto.Random as R
import Prelude (show)
#endif

data Opts = Opts
  {
    checksum :: Bool
  , generate :: Bool
  , sign :: Bool
  , verify :: Bool
  , pubkey :: Maybe FilePath
  , seckey :: Maybe FilePath
  , sigfile :: Maybe FilePath
  , message :: Maybe String
  , quiet :: Bool
  , comment :: String
  , embedmsg :: Bool
  , nopassphrase :: Bool
  , keytype :: Maybe String
  , gzipembed :: Bool
  , files :: [FilePath]
  }

options :: Parser Opts
options = Opts
  <$> switch
  (short 'C'
    <> help "Verify a signed checksum list, and then verify the checksum for each file." )
  <*> switch
  (short 'G'
    <> help "Generate a new key pair." )
  <*> switch
  (short 'S'
    <> help "Sign the specified message file and create a signature." )
  <*> switch
  (short 'V'
    <> help "Verify the message and signature match." )
  <*> optional (strOption
  (short 'p'
    <> help "Public key"
    <> metavar "pubkey"))
  <*> optional (strOption
  (short 's'
    <> help "Secret Key"
    <> metavar "seckey"))
  <*> optional (strOption
  (short 'x'
    <> help "Signature file to create or verify"
    <> metavar "sigfile"))
  <*> optional (strOption
  (short 'm'
    <> help "message"
    <> metavar "message"))
  <*> switch
  (short 'q'
    <> help "Whether to be quiet" )
  <*> strOption
  (short 'c'
    <> value "signify"
    <> help "comment"
    <> metavar "comment")
  <*> switch
  (short 'e'
    <> help "when signing, embed message after signature" )
  <*> switch
  (short 'n'
    <> help "don't force a passphrase" )
  <*> optional (strOption
  (short 't'
    <> help "keytypes???"
    <> metavar "keytype"))
  <*> switch
  (short 'z'
    <> help "sign and verify gzip archives, signing data embedded in the header" )
  <*> many (argument str (metavar "file ..."))

-- The horror of option combinations is contained here
main :: IO ()
-- main = do signify =<< customExecParser (prefs showHelpOnError) opts
main = signify =<< execParser opts
  where
    opts = info (options <**> helper)
      ( fullDesc
     <> progDesc "cryptographically sign and verify files"
     <> header "signify-hs, a Haskell clone of signify-openbsd" )

signify :: Opts -> IO ()
signify (Opts _ _ _ _ _ _ _ _ _ _ _ _ _ True _)
  = do putStrLn "gzip embedding not supported, yet"
       wrong
signify (Opts True _ _ _ _ _ Nothing _ q _ _ _ _ _ _)
  = do unless q $ putStrLn "must specify sigfile"
       wrong
signify (Opts True _ _ _ pub _ (Just sigfile') _ q _ _ _ _ _ files')
  = do putStrLn "Checksum file mode not supported, yet"
       wrong
signify (Opts _ True _ _ pub sec _ _ _ comment' _ nopass _ _ _)
  | isNothing pub || isNothing sec = putStrLn "must specify pubkey and seckey" >> wrong
  | otherwise = do
      passphrase <- if nopass then return B.empty else getcreatepassphrase
      keys <- Ed.genkeys
      case keys of
        Left e -> print e >> exitFailure
        Right (seck,pubk) ->
          do
#ifndef mingw32_HOST_OS
            bytes <- BS8.readFile "/dev/urandom"
            let salt = BS8.toStrict $ BS8.take 16 bytes
                keyID = BS8.toStrict $ BS8.take 8 $ BS8.drop 16 bytes
#else
            g <- R.getStdGen
            let bytes = R.randoms g
                salt = BS.pack $ BS8.take 16 bytes
                keyID = BS8.toStrict $ BS8.take 8 $ BS8.drop 16 bytes
#endif
            B.writeFile (fromMaybe "" pub) $ printPubKey keyID pubk comment'
            B.writeFile (fromMaybe "" sec) $ printSecKey keyID passphrase salt seck pubk comment'
signify (Opts _ _ True _ _ sec sig message' _ _ embed nopass _ gzipembed' _)
  | isNothing sec || isNothing message' = putStrLn "must specify message and seckey" >> wrong
signify (Opts _ _ True _ _ (Just secfile) sig (Just messagefile) _ _ embed nopass _ gzipembed' _) = do
      let targetfile = if isNothing sig then messagefile ++ ".sig" else let (Just sigfile') = sig in sigfile'
      passphrase <- if nopass then return B.empty else getpassphrase
      seccontent <- parseSecKey passphrase <$> B.readFile secfile
      case seccontent of
        Left e -> putStrLn e >> exitFailure
        Right (_, keyid, secKeyAndPubKey) -> do
          msgs <- B.readFile messagefile
          let comment' = "verify with " ++ takeBaseName secfile ++ ".pub"
              s = Ed.dsign secKeyAndPubKey msgs
          case s of
            Right sigs -> B.writeFile targetfile $ printSignature keyid sigs comment' `B.append` if embed then msgs else B.empty
            Left e -> putStrLn e >> exitFailure
signify (Opts _ _ _ True _ _ _ Nothing _ _ _ _ _ _ _)
  = putStrLn "must specify message" >> wrong
signify (Opts _ _ _ True pub _ sig (Just msgfile) q _ embed _ _ gzipembed' _)
  = do
  sigs <- case sig of
    Nothing -> parseSignature <$> B.readFile (msgfile ++ ".sig")
    Just sigfile' -> parseSignature <$> B.readFile sigfile'
  msgs <- B.readFile msgfile
  case sigs of
    Left _ -> wrong
    Right (comments, keyids, sig') -> do
      pubs <- case pub of
        Nothing -> let filep = drop 12 comments
                   in parsePubKey <$> B.readFile ("/etc/signify/" ++ filep)
        Just pubfile -> parsePubKey <$> B.readFile pubfile
      case pubs of
        Left _ -> wrong
        Right (commentp, keyidp, pub') ->
          let x = Ed.dverify pub' sig' msgs
          in case x of
            Right Ed.SigOK -> unless q $ putStrLn "Signature Verified"
            _ -> do unless q $ putStrLn "signature verification failed"
                    exitFailure
signify _ = wrong

wrong :: IO ()
wrong = printUsage >> exitFailure

printUsage :: IO ()
printUsage = do
  putStrLn "usage:\tsignify-hs -C [-q] [-p pubkey] [-t keytype] -x sigfile [file ...]"
  putStrLn "\tsignify-hs -G [-n] [-c comment] -p pubkey -s seckey"
  putStrLn "\tsignify-hs -S [-enz] [-x sigfile] -s seckey -m message"
  putStrLn "\tsignify-hs -V [-eqz] [-p pubkey] [-t keytype] [-x sigfile] -m message"
--  putStrLn "help:\tsignify-hs [-h|--help]"

getcreatepassphrase :: IO B.ByteString
getcreatepassphrase = do
  hSetEcho stdin False
  passphrase <- getpassphrase
  putStr "confirm passphrase: "
  hFlush stdout
  passphrase2 <- B.getLine
  putStrLn ""
  if passphrase == passphrase2
    then return passphrase
    else do name <- getProgName
            putStrLn $ name ++ ": passwords don't match"
            exitFailure

getpassphrase :: IO B.ByteString
getpassphrase = do
  hSetEcho stdin False
  putStr "passphrase: "
  hFlush stdout
  passphrase <- B.getLine
  putStrLn ""
  return passphrase
