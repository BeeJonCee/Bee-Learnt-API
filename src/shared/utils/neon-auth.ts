import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { env } from "../../config/env.js";

let cachedIssuer: string | null = null;
let cachedJwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getIssuer() {
  if (!env.neonAuthBaseUrl) return null;
  if (!cachedIssuer) {
    cachedIssuer = env.neonAuthBaseUrl.replace(/\/+$/, "");
  }
  return cachedIssuer;
}

function getJwks() {
  if (!cachedJwks) {
    const issuer = getIssuer();
    if (!issuer) return null;
    cachedJwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  }
  return cachedJwks;
}

export async function verifyNeonToken(token: string): Promise<JWTPayload | null> {
  const issuer = getIssuer();
  const jwks = getJwks();
  if (!issuer || !jwks) return null;

  try {
    const { payload } = await jwtVerify(token, jwks, { issuer });
    return payload;
  } catch {
    try {
      const { payload } = await jwtVerify(token, jwks);
      return payload;
    } catch {
      return null;
    }
  }
}
