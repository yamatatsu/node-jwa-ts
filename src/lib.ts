// @ts-ignore
import bufferEqual from "buffer-equal-constant-time"
import { Buffer } from "safe-buffer"
import util from "util"

const MSG_INVALID_SECRET = "secret must be a string or buffer or a KeyObject"
const MSG_INVALID_VERIFIER_KEY =
  "key must be a string or a buffer or a KeyObject"
const MSG_INVALID_SIGNER_KEY = "key must be a string, a buffer or an object"

export function checkIsPublicKey(key: any) {
  if (Buffer.isBuffer(key)) return
  if (typeof key === "string") return

  if (
    typeof key !== "object" ||
    typeof key.type !== "string" ||
    typeof key.asymmetricKeyType !== "string" ||
    typeof key.export !== "function"
  ) {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }
}

export function checkIsPrivateKey(key: any) {
  if (Buffer.isBuffer(key)) return
  if (typeof key === "string") return
  if (typeof key === "object") return

  throw typeError(MSG_INVALID_SIGNER_KEY)
}

export function checkIsSecretKey(key: any) {
  if (Buffer.isBuffer(key)) return
  if (typeof key === "string") return

  if (
    typeof key !== "object" ||
    key.type !== "secret" ||
    typeof key.export !== "function"
  ) {
    throw typeError(MSG_INVALID_SECRET)
  }
}

export function fromBase64(base64: string) {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

export function toBase64(base64url: string) {
  const padding = 4 - (base64url.length % 4)
  if (padding !== 4) {
    base64url += "=".repeat(padding)
  }

  return base64url.replace(/\-/g, "+").replace(/_/g, "/")
}

export function typeError(template: string, ...args: any[]) {
  const errMsg = util.format(template, args)
  return new TypeError(errMsg)
}
