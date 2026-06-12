/**
 * Protocol-conformance test: a real relying-party library
 * (@simplewebauthn/server) verifies the registration and authentication
 * output of the nopwd software authenticator, exactly as a website's backend
 * would. This catches CBOR/COSE/authData/DER mistakes no unit test can.
 */
// @vitest-environment node
import { describe, it, expect } from "vitest";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import {
  generateCredential,
  buildAuthenticatorData,
  buildAttestationObject,
  signAssertion,
  bytesToB64u,
  FLAG_UP,
  FLAG_UV,
  SYNCED_FLAGS,
} from "../webauthn";

const te = new TextEncoder();
const RP_ID = "example.com";
const ORIGIN = "https://example.com";

function clientDataJson(type: "webauthn.create" | "webauthn.get", challengeB64u: string): string {
  return JSON.stringify({ type, challenge: challengeB64u, origin: ORIGIN, crossOrigin: false });
}

describe("WebAuthn conformance against @simplewebauthn/server", () => {
  it("registration and authentication round-trip verify like a real RP", async () => {
    // ── Registration (what WEBAUTHN_CREATE produces) ──
    const challenge = new Uint8Array(32).fill(7);
    const challengeB64u = bytesToB64u(challenge);

    const cred = await generateCredential();
    const regAuthData = await buildAuthenticatorData(
      RP_ID,
      FLAG_UP | FLAG_UV | SYNCED_FLAGS,
      0,
      { credentialId: cred.credentialId, cosePublicKey: cred.cosePublicKey },
    );
    const attestationObject = buildAttestationObject(regAuthData);
    const regClientData = clientDataJson("webauthn.create", challengeB64u);

    const registration = await verifyRegistrationResponse({
      response: {
        id: bytesToB64u(cred.credentialId),
        rawId: bytesToB64u(cred.credentialId),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: bytesToB64u(te.encode(regClientData)),
          attestationObject: bytesToB64u(attestationObject),
          transports: ["hybrid", "internal"],
        },
      },
      expectedChallenge: challengeB64u,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });

    expect(registration.verified).toBe(true);
    const info = registration.registrationInfo!;
    expect(info.credential.id).toBe(bytesToB64u(cred.credentialId));
    expect(info.credentialDeviceType).toBe("multiDevice");
    expect(info.credentialBackedUp).toBe(true);

    // ── Authentication (what WEBAUTHN_GET produces) ──
    const authChallenge = new Uint8Array(32).fill(9);
    const authChallengeB64u = bytesToB64u(authChallenge);
    const authClientData = clientDataJson("webauthn.get", authChallengeB64u);

    const newCount = 1;
    const assertAuthData = await buildAuthenticatorData(
      RP_ID,
      FLAG_UP | FLAG_UV | SYNCED_FLAGS,
      newCount,
    );
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", te.encode(authClientData)),
    );
    const signature = await signAssertion(cred.privateKeyPkcs8, assertAuthData, clientDataHash);

    const authentication = await verifyAuthenticationResponse({
      response: {
        id: bytesToB64u(cred.credentialId),
        rawId: bytesToB64u(cred.credentialId),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: bytesToB64u(te.encode(authClientData)),
          authenticatorData: bytesToB64u(assertAuthData),
          signature: bytesToB64u(signature),
          userHandle: bytesToB64u(te.encode("user-123")),
        },
      },
      expectedChallenge: authChallengeB64u,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: info.credential.id,
        publicKey: info.credential.publicKey,
        counter: info.credential.counter,
      },
      requireUserVerification: true,
    });

    expect(authentication.verified).toBe(true);
    expect(authentication.authenticationInfo.newCounter).toBe(newCount);
  });

  it("a tampered signature is rejected by the RP", async () => {
    const challenge = bytesToB64u(new Uint8Array(32).fill(3));
    const cred = await generateCredential();
    const regAuthData = await buildAuthenticatorData(RP_ID, FLAG_UP | FLAG_UV | SYNCED_FLAGS, 0, {
      credentialId: cred.credentialId,
      cosePublicKey: cred.cosePublicKey,
    });
    const reg = await verifyRegistrationResponse({
      response: {
        id: bytesToB64u(cred.credentialId),
        rawId: bytesToB64u(cred.credentialId),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: bytesToB64u(te.encode(clientDataJson("webauthn.create", challenge))),
          attestationObject: bytesToB64u(buildAttestationObject(regAuthData)),
        },
      },
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    const authChallenge = bytesToB64u(new Uint8Array(32).fill(4));
    const cdj = clientDataJson("webauthn.get", authChallenge);
    const authData = await buildAuthenticatorData(RP_ID, FLAG_UP | FLAG_UV | SYNCED_FLAGS, 1);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(cdj)));
    const signature = await signAssertion(cred.privateKeyPkcs8, authData, hash);
    signature[signature.length - 1]! ^= 0xff;

    await expect(
      verifyAuthenticationResponse({
        response: {
          id: bytesToB64u(cred.credentialId),
          rawId: bytesToB64u(cred.credentialId),
          type: "public-key",
          clientExtensionResults: {},
          response: {
            clientDataJSON: bytesToB64u(te.encode(cdj)),
            authenticatorData: bytesToB64u(authData),
            signature: bytesToB64u(signature),
          },
        },
        expectedChallenge: authChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: reg.registrationInfo!.credential.id,
          publicKey: reg.registrationInfo!.credential.publicKey,
          counter: 0,
        },
      }).then((r) => (r.verified ? Promise.resolve(true) : Promise.reject(new Error("not verified")))),
    ).rejects.toThrow();
  });
});
