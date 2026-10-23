// Regenerates the cross-implementation OPAQUE fixture used by
// crates/nopass-crypto/tests/opaque_compat.rs. The record is produced by the
// serenity (wasm) client, so the Rust test only passes if our opaque-ke cipher
// suite and Argon2id KSF match what the clients actually run.
//
//   node packages/crypto/scripts/gen-opaque-fixture.mjs > crates/nopass-crypto/tests/fixtures/serenity-opaque.json
import * as opaque from "@serenity-kit/opaque";

await opaque.ready;

const password = "correct horse battery staple";
const credentialId = "a3f1c0de".repeat(8);
// Cheap parameters keep the test fast; the parameter plumbing is what's under test.
const ksf = { iterations: 1, memory: 1024, parallelism: 1 };

const serverSetup = opaque.server.createSetup();
const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password });
const { registrationResponse } = opaque.server.createRegistrationResponse({
  serverSetup,
  userIdentifier: credentialId,
  registrationRequest,
});
const { registrationRecord, exportKey } = opaque.client.finishRegistration({
  clientRegistrationState,
  registrationResponse,
  password,
  keyStretching: { "argon2id-custom": ksf },
});

// A login half-run by serenity on both sides: the Rust test finishes it as the
// client, which only works if our key-exchange hash matches serenity's server.
const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
const { loginResponse } = opaque.server.startLogin({
  serverSetup,
  registrationRecord,
  startLoginRequest,
  userIdentifier: credentialId,
});

console.log(
  JSON.stringify(
    {
      password,
      credentialId,
      ksf,
      serverSetup,
      registrationRecord,
      exportKey,
      clientLoginState,
      loginResponse,
    },
    null,
    2,
  ),
);
