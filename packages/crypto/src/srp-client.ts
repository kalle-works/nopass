/**
 * SRP-6a client implementation using the `secure-remote-password` npm package.
 *
 * Registration: client computes verifier and sends it to server.
 * Login step 1: client sends ephemeral public A.
 * Login step 2: client verifies server proof M2 and considers session authenticated.
 */
import srpClient from "secure-remote-password/client";
import srpVerifierHelpers from "secure-remote-password/client";

export interface SrpRegistrationMaterial {
  srpSalt: string;
  srpVerifier: string;
}

export interface SrpStep1Result {
  clientPublicA: string;
  /** Keep in memory only — never log or store */
  privateSession: ReturnType<typeof srpClient.generateEphemeral>;
}

export interface SrpStep2Result {
  clientProofM1: string;
  /** Verify this against server's M2 to confirm the server knows the verifier */
  verifyServerProof: (serverM2: string) => void;
}

/**
 * Generate SRP registration material. Called once during account creation.
 * The verifier is derived from password via Argon2id (done externally),
 * so we use `srpSalt` as a random salt for the SRP layer only.
 */
export function generateSrpRegistration(
  email: string,
  masterPassword: string,
): SrpRegistrationMaterial {
  const srpSalt = srpClient.generateSalt();
  const privateKey = srpClient.derivePrivateKey(srpSalt, email, masterPassword);
  const srpVerifier = srpClient.deriveVerifier(privateKey);

  return { srpSalt, srpVerifier };
}

/** Step 1: generate client ephemeral and public A to send to server */
export function srpStep1(): SrpStep1Result {
  const privateSession = srpClient.generateEphemeral();
  return {
    clientPublicA: privateSession.public,
    privateSession,
  };
}

/** Step 2: produce client proof M1 and a function to verify server proof M2 */
export function srpStep2(
  email: string,
  masterPassword: string,
  srpSalt: string,
  serverPublicB: string,
  privateSession: SrpStep1Result["privateSession"],
): SrpStep2Result {
  const privateKey = srpClient.derivePrivateKey(srpSalt, email, masterPassword);
  const clientSession = srpClient.deriveSession(
    privateSession.secret,
    serverPublicB,
    srpSalt,
    email,
    privateKey,
  );

  return {
    clientProofM1: clientSession.proof,
    verifyServerProof: (serverM2: string) => {
      srpClient.verifySession(privateSession.public, clientSession, serverM2);
      // verifySession throws if verification fails
    },
  };
}
