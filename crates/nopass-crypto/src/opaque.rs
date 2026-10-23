/// OPAQUE (RFC 9807) server side, wire-compatible with `@serenity-kit/opaque`
/// (the wasm build of opaque-ke the clients use). Both sides must agree on the
/// cipher suite below and on the Argon2id KSF parameters, which the client
/// takes from the account's `kdf_params` so the KSF costs the same as the
/// vault KDF.
///
/// Messages are passed around as raw bytes; the API layer handles the
/// base64url encoding serenity uses on the wire.
use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand::rngs::OsRng;

use crate::{Argon2Params, CryptoError};

pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub type ServerSetup = opaque_ke::ServerSetup<Suite>;

fn opaque_err(context: &str) -> impl Fn(opaque_ke::errors::ProtocolError) -> CryptoError + '_ {
    move |e| CryptoError::Opaque(format!("{context}: {e:?}"))
}

/// The client-side KSF. The server never runs it; it lives here so Rust
/// clients (and tests) stretch exactly like serenity's `argon2id-custom`.
pub fn ksf(params: &Argon2Params) -> Result<Argon2<'static>, CryptoError> {
    let params = Params::new(params.memory_kib, params.iterations, params.parallelism, None)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Fresh server setup (OPRF seed, AKE keypair, fake-record keypair). Generated
/// once per deployment and loaded from a secret; rotating it invalidates every
/// registration record.
pub fn generate_server_setup() -> Vec<u8> {
    ServerSetup::new(&mut OsRng).serialize().to_vec()
}

pub fn parse_server_setup(bytes: &[u8]) -> Result<ServerSetup, CryptoError> {
    ServerSetup::deserialize(bytes).map_err(opaque_err("server setup"))
}

/// Registration round 1: evaluate the client's blinded password under the
/// per-credential OPRF key.
pub fn registration_start(
    setup: &ServerSetup,
    registration_request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let request = RegistrationRequest::<Suite>::deserialize(registration_request)
        .map_err(opaque_err("registration request"))?;
    let result = ServerRegistration::start(setup, request, credential_id)
        .map_err(opaque_err("registration start"))?;
    Ok(result.message.serialize().to_vec())
}

/// Registration round 2: validate the client's upload and return the record
/// to store.
pub fn registration_finish(registration_upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let upload = RegistrationUpload::<Suite>::deserialize(registration_upload)
        .map_err(opaque_err("registration upload"))?;
    Ok(ServerRegistration::finish(upload).serialize().to_vec())
}

pub struct LoginStart {
    pub response: Vec<u8>,
    /// Server AKE state — persisted until finish, never sent to the client.
    pub state: Vec<u8>,
}

/// Login round 1. `record: None` makes opaque-ke answer with a fake record
/// derived from the server setup and `credential_id`, indistinguishable from a
/// real one, so unknown accounts can't be told apart from known ones.
pub fn login_start(
    setup: &ServerSetup,
    record: Option<&[u8]>,
    credential_request: &[u8],
    credential_id: &[u8],
) -> Result<LoginStart, CryptoError> {
    let record = record
        .map(ServerRegistration::<Suite>::deserialize)
        .transpose()
        .map_err(opaque_err("registration record"))?;
    let request = CredentialRequest::<Suite>::deserialize(credential_request)
        .map_err(opaque_err("credential request"))?;
    let result = ServerLogin::start(
        &mut OsRng,
        setup,
        record,
        request,
        credential_id,
        ServerLoginParameters::default(),
    )
    .map_err(opaque_err("login start"))?;
    Ok(LoginStart {
        response: result.message.serialize().to_vec(),
        state: result.state.serialize().to_vec(),
    })
}

/// Login round 2: succeeds only if the client proved knowledge of the password.
pub fn login_finish(state: &[u8], credential_finalization: &[u8]) -> Result<(), CryptoError> {
    let state = ServerLogin::<Suite>::deserialize(state).map_err(opaque_err("login state"))?;
    let finalization = CredentialFinalization::<Suite>::deserialize(credential_finalization)
        .map_err(opaque_err("credential finalization"))?;
    state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(opaque_err("login finish"))?;
    Ok(())
}
