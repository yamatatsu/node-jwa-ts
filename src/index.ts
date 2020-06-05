// @ts-ignore
import bufferEqual from "buffer-equal-constant-time"
import { Buffer } from "safe-buffer"
import crypto from "crypto"
import formatEcdsa from "ecdsa-sig-formatter"
import {
  checkIsPublicKey,
  checkIsPrivateKey,
  checkIsSecretKey,
  fromBase64,
  toBase64,
  typeError,
} from "./lib"

const MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'

type Sign = (thing: string, secret: any) => string
type Verify = (thing: string, signature: string, secret: any) => boolean

function createHmacSigner(bits: string): Sign {
  return (thing, secret) => {
    checkIsSecretKey(secret)

    const hmac = crypto.createHmac("sha" + bits, secret)
    const sig = (hmac.update(thing), hmac.digest("base64"))
    return fromBase64(sig)
  }
}

function createHmacVerifier(bits: string): Verify {
  return (thing, signature, secret) => {
    const computedSig = createHmacSigner(bits)(thing, secret)
    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig))
  }
}

function createKeySigner(bits: string): Sign {
  return (thing, privateKey) => {
    checkIsPrivateKey(privateKey)

    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = crypto.createSign("RSA-SHA" + bits)
    const sig = (signer.update(thing), signer.sign(privateKey, "base64"))
    return fromBase64(sig)
  }
}

function createKeyVerifier(bits: string): Verify {
  return (thing, signature, publicKey) => {
    checkIsPublicKey(publicKey)

    signature = toBase64(signature)
    const verifier = crypto.createVerify("RSA-SHA" + bits)
    verifier.update(thing)
    return verifier.verify(publicKey, signature, "base64")
  }
}

function createPSSKeySigner(bits: string): Sign {
  return (thing, privateKey) => {
    checkIsPrivateKey(privateKey)

    const signer = crypto.createSign("RSA-SHA" + bits)
    const sig =
      (signer.update(thing),
      signer.sign(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        "base64",
      ))
    return fromBase64(sig)
  }
}

function createPSSKeyVerifier(bits: string): Verify {
  return (thing, signature, publicKey) => {
    checkIsPublicKey(publicKey)

    signature = toBase64(signature)
    const verifier = crypto.createVerify("RSA-SHA" + bits)
    verifier.update(thing)
    return verifier.verify(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      signature,
      "base64",
    )
  }
}

function createECDSASigner(bits: string): Sign {
  const inner = createKeySigner(bits)
  return (thing, secret) => {
    const signature = formatEcdsa.derToJose(inner(thing, secret), "ES" + bits)
    return signature
  }
}

function createECDSAVerifer(bits: string): Verify {
  const inner = createKeyVerifier(bits)
  return (thing, signature, publicKey) => {
    signature = formatEcdsa.joseToDer(signature, "ES" + bits).toString("base64")
    const result = inner(thing, signature, publicKey)
    return result
  }
}

function createNoneSigner(): Sign {
  return () => ""
}

function createNoneVerifier(): Verify {
  return (_: any, signature: any) => signature === ""
}

export default function jwa(algorithm: string) {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner,
  }
  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier,
  }
  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/)
  if (!match) throw typeError(MSG_INVALID_ALGORITHM, algorithm)
  const algo = (match[1] || match[3]).toLowerCase() as
    | "rs"
    | "ps"
    | "es"
    | "hs"
    | "none"
  const bits = match[2]

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits),
  }
}
