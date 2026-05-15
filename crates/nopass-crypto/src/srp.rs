/// SRP-6a server-side implementation wrapping the `srp` crate.
///
/// Round 1 (init):   client sends A → server computes B, stores (b, verifier) in pending session
/// Round 2 (verify): client sends M1 → server verifies and returns M2
use rand::RngCore;
use sha2::Sha256;
use srp::{groups::G_2048, server::SrpServer};

use crate::CryptoError;

pub struct ServerInitResult {
    /// Base64-ready server public ephemeral B to send to client
    pub server_public_b: Vec<u8>,
    /// Private ephemeral b — must be stored in the pending session, never transmitted
    pub server_ephemeral_b: Vec<u8>,
}

/// Round 1: generate server ephemeral and compute public B.
pub fn srp_server_init(verifier: &[u8]) -> Result<ServerInitResult, CryptoError> {
    let server = SrpServer::<Sha256>::new(&G_2048);

    let mut b = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut b);

    let server_public_b = server.compute_public_ephemeral(&b, verifier);

    Ok(ServerInitResult {
        server_public_b,
        server_ephemeral_b: b,
    })
}

pub struct ServerVerifyResult {
    /// Server proof M2 to send back to client
    pub server_proof_m2: Vec<u8>,
    /// Shared session key (for optional MAC of the session)
    pub session_key: Vec<u8>,
}

/// Round 2: verify client proof M1 and produce server proof M2.
pub fn srp_server_verify(
    verifier: &[u8],
    server_ephemeral_b: &[u8],
    client_public_a: &[u8],
    client_proof_m1: &[u8],
) -> Result<ServerVerifyResult, CryptoError> {
    let server = SrpServer::<Sha256>::new(&G_2048);

    let srv_verifier = server
        .process_reply(server_ephemeral_b, verifier, client_public_a)
        .map_err(|e| CryptoError::Srp(format!("process_reply: {e:?}")))?;

    srv_verifier
        .verify_client(client_proof_m1)
        .map_err(|_| CryptoError::Srp("client proof M1 invalid".into()))?;

    Ok(ServerVerifyResult {
        server_proof_m2: srv_verifier.proof().to_vec(),
        session_key: srv_verifier.key().to_vec(),
    })
}
