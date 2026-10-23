//! The clients run @serenity-kit/opaque (wasm). These tests take a record the
//! serenity client produced (fixtures/serenity-opaque.json, regenerate with
//! packages/crypto/scripts/gen-opaque-fixture.mjs) and log in against it with
//! our Rust suite. Any drift in cipher suite, KSF or serialization breaks them.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use nopass_crypto::{
    opaque::{self, Suite},
    Argon2Params,
};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use rand::rngs::OsRng;

struct Fixture {
    password: String,
    credential_id: Vec<u8>,
    ksf: Argon2Params,
    server_setup: Vec<u8>,
    record: Vec<u8>,
    export_key: Vec<u8>,
    client_login_state: Vec<u8>,
    login_response: Vec<u8>,
}

fn fixture() -> Fixture {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/serenity-opaque.json")).unwrap();
    let b = |k: &str| B64URL.decode(v[k].as_str().unwrap()).unwrap();
    Fixture {
        password: v["password"].as_str().unwrap().into(),
        credential_id: v["credentialId"].as_str().unwrap().as_bytes().to_vec(),
        ksf: Argon2Params {
            memory_kib: v["ksf"]["memory"].as_u64().unwrap() as u32,
            iterations: v["ksf"]["iterations"].as_u64().unwrap() as u32,
            parallelism: v["ksf"]["parallelism"].as_u64().unwrap() as u32,
        },
        server_setup: b("serverSetup"),
        record: b("registrationRecord"),
        export_key: b("exportKey"),
        client_login_state: b("clientLoginState"),
        login_response: b("loginResponse"),
    }
}

/// Runs a full login; returns the client's export key, or None if either side rejected.
fn login(f: &Fixture, password: &str, record: Option<&[u8]>) -> Option<Vec<u8>> {
    let setup = opaque::parse_server_setup(&f.server_setup).unwrap();
    let client = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
    let server = opaque::login_start(
        &setup,
        record,
        &client.message.serialize(),
        &f.credential_id,
    )
    .unwrap();

    let ksf = opaque::ksf(&f.ksf).unwrap();
    let finished = client
        .state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            CredentialResponse::deserialize(&server.response).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf)),
        )
        .ok()?;
    opaque::login_finish(&server.state, &finished.message.serialize()).ok()?;
    Some(finished.export_key.to_vec())
}

#[test]
fn serenity_registered_record_logs_in_with_rust_suite() {
    let f = fixture();
    let export_key = login(&f, &f.password, Some(&f.record)).expect("login must succeed");
    // Same export key as the wasm client derived proves the KSF output matches too.
    assert_eq!(export_key, f.export_key);
}

#[test]
fn rust_client_accepts_serenity_server_response() {
    let f = fixture();
    let ksf = opaque::ksf(&f.ksf).unwrap();
    let finished = ClientLogin::<Suite>::deserialize(&f.client_login_state)
        .unwrap()
        .finish(
            &mut OsRng,
            f.password.as_bytes(),
            CredentialResponse::deserialize(&f.login_response).unwrap(),
            ClientLoginFinishParameters::new(None, Default::default(), Some(&ksf)),
        )
        .expect("serenity server MAC must verify under our key-exchange suite");
    assert_eq!(finished.export_key.to_vec(), f.export_key);
}

#[test]
fn wrong_password_is_rejected() {
    let f = fixture();
    assert!(login(&f, "correct horse battery stapler", Some(&f.record)).is_none());
}
