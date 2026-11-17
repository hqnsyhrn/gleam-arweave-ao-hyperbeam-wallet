import { addressFromOwner } from "./address";
import type { JWKInterface } from "../models/wallet";
import { userErrorMessage } from "../models/user-errors";
import { base64UrlToBytes } from "../vault/base64";

const REQUIRED_JWK_FIELDS = ["kty", "e", "n", "d", "p", "q", "dp", "dq", "qi"] as const;

/** Arweave keys are RSA-4096: a 512-byte modulus, public exponent 65537. */
const RSA_MODULUS_BYTES = 512;
const RSA_PUBLIC_EXPONENT = "AQAB";

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/**
 * Derives the Arweave address for a JWK. Deterministic: the same JWK
 * always yields the same address.
 */
export async function deriveAddress(jwk: JWKInterface): Promise<string> {
  return addressFromOwner(jwk.n);
}

export type JWKValidationResult =
  | { valid: true; jwk: JWKInterface }
  | { valid: false; reason: string };

/**
 * Validates that `input` (typically `JSON.parse`d from an imported
 * keyfile) has the shape of an RSA Arweave JWK, returning a specific
 * rejection reason rather than a generic error.
 */
export function validateJWKShape(input: unknown): JWKValidationResult {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return { valid: false, reason: userErrorMessage("keyfileInvalid") };
  }

  const candidate = input as Record<string, unknown>;

  for (const field of REQUIRED_JWK_FIELDS) {
    if (!(field in candidate)) {
      return {
        valid: false,
        reason: userErrorMessage("keyfileMissingField", { key: field }),
      };
    }
  }

  if (candidate.kty !== "RSA") {
    return {
      valid: false,
      reason: userErrorMessage("keyfileWrongKeyType", { kty: String(candidate.kty) }),
    };
  }

  for (const field of REQUIRED_JWK_FIELDS) {
    if (field === "kty") continue;
    const value = candidate[field];
    if (typeof value !== "string" || value.length === 0) {
      return {
        valid: false,
        reason: userErrorMessage("keyfileEmptyField", { key: field }),
      };
    }
    if (!BASE64URL_PATTERN.test(value)) {
      return {
        valid: false,
        reason: userErrorMessage("keyfileBadField", { key: field }),
      };
    }
  }

  // A short modulus is factorable, and the public key is published in
  // every transaction, so a weak key is a silent downgrade to no
  // security at all. The hardware-wallet path already enforces this
  // length; import must not be the one entry that doesn't.
  if (candidate.e !== RSA_PUBLIC_EXPONENT) {
    return {
      valid: false,
      reason: userErrorMessage("keyfileWrongExponent", { e: String(candidate.e) }),
    };
  }

  let modulus: Uint8Array;
  try {
    modulus = base64UrlToBytes(candidate.n as string);
  } catch {
    return {
      valid: false,
      reason: userErrorMessage("keyfileBadField", { key: "n" }),
    };
  }
  if (modulus.length !== RSA_MODULUS_BYTES) {
    return {
      valid: false,
      reason: userErrorMessage("keyfileWrongModulusLength", { size: modulus.length }),
    };
  }

  return {
    valid: true,
    jwk: {
      kty: candidate.kty as string,
      e: candidate.e as string,
      n: candidate.n as string,
      d: candidate.d as string,
      p: candidate.p as string,
      q: candidate.q as string,
      dp: candidate.dp as string,
      dq: candidate.dq as string,
      qi: candidate.qi as string,
    },
  };
}
