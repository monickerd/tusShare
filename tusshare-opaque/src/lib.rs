//! tusshare-opaque: PyO3 bindings to opaque-ke for the tusShare server.
//!
//! All functions take and return raw bytes (`Vec<u8>` / `&[u8]`), keeping all
//! crypto in Rust while letting Python drive the protocol flow.  Every function
//! releases the GIL for the duration of the crypto work via `allow_threads`.
//!
//! ## CipherSuite
//! Ristretto255 VOPRF · TripleDH key-exchange with SHA-512 · Argon2id KSF.
//!
//! ## Wire encoding
//! All *protocol messages* (registration_request, registration_response, etc.)
//! use the fixed-size serialization built into opaque-ke (`.serialize()` /
//! `Type::deserialize()`).  The server-side login *state* (which must survive
//! between the two login round-trips) is serialized with bincode.
//!
//! ## Identifiers
//! Registration and login both bind `username` as the client identifier and the
//! ASCII string `"tusshare"` as the server identifier.  These MUST be identical
//! on both sides or the key-exchange MAC will reject.

use argon2::Argon2;
use opaque_ke::{
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use opaque_ke::ciphersuite::CipherSuite;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rand::rngs::OsRng;
use sha2::Sha512;

// ---------------------------------------------------------------------------
// Cipher suite
// ---------------------------------------------------------------------------

struct TusShareCipherSuite;

impl CipherSuite for TusShareCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SERVER_ID: &[u8] = b"tusshare";

fn identifiers(username: &[u8]) -> Identifiers<'_> {
    Identifiers {
        client: Some(username),
        server: Some(SERVER_ID),
    }
}

fn proto_err(e: impl std::fmt::Debug) -> PyErr {
    PyValueError::new_err(format!("OPAQUE protocol error: {e:?}"))
}

fn bincode_err(e: impl std::fmt::Debug) -> PyErr {
    PyValueError::new_err(format!("state (de)serialization error: {e:?}"))
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Generate a new `ServerSetup` and return it serialized.
///
/// Call once at first startup; persist the result in `sensitive_config` under
/// the key `opaque.server_setup`.  Treat this blob like a CA private key —
/// if it leaks an attacker can run offline dictionary attacks against every
/// stored `opaque_registration_record`.
#[pyfunction]
fn generate_server_setup(py: Python<'_>) -> PyResult<Vec<u8>> {
    py.allow_threads(|| {
        let mut rng = OsRng;
        let setup = ServerSetup::<TusShareCipherSuite>::new(&mut rng);
        Ok(setup.serialize().to_vec())
    })
}

/// Registration round 1 (server side).
///
/// Args:
///   server_setup  – serialized `ServerSetup` from `sensitive_config`
///   reg_request   – `RegistrationRequest` bytes sent by the client
///   username      – raw username bytes (used as client identifier)
///
/// Returns the `RegistrationResponse` bytes to send back to the client.
/// No server state needs to be persisted between rounds.
#[pyfunction]
fn server_start_registration(
    py: Python<'_>,
    server_setup: &[u8],
    reg_request: &[u8],
    username: &[u8],
) -> PyResult<Vec<u8>> {
    // Copy to owned so we can move into allow_threads.
    let server_setup = server_setup.to_vec();
    let reg_request = reg_request.to_vec();
    let username = username.to_vec();

    py.allow_threads(move || {
        let setup = ServerSetup::<TusShareCipherSuite>::deserialize(&server_setup)
            .map_err(proto_err)?;
        let request = RegistrationRequest::<TusShareCipherSuite>::deserialize(&reg_request)
            .map_err(proto_err)?;
        let result = ServerRegistration::<TusShareCipherSuite>::start(
            &setup,
            request,
            &username,
        )
        .map_err(proto_err)?;
        Ok(result.message.serialize().to_vec())
    })
}

/// Registration round 2 (server side).
///
/// Args:
///   reg_upload – `RegistrationUpload` bytes sent by the client
///
/// Returns the `RegistrationRecord` bytes to store in `users.opaque_registration_record`.
/// This is a static operation — no `ServerSetup` or prior server state required.
#[pyfunction]
fn server_finish_registration(py: Python<'_>, reg_upload: &[u8]) -> PyResult<Vec<u8>> {
    let reg_upload = reg_upload.to_vec();

    py.allow_threads(move || {
        let upload = RegistrationUpload::<TusShareCipherSuite>::deserialize(&reg_upload)
            .map_err(proto_err)?;
        let record = ServerRegistration::<TusShareCipherSuite>::finish(upload);
        Ok(record.serialize().to_vec())
    })
}

/// Login round 1 (server side).
///
/// Args:
///   server_setup    – serialized `ServerSetup` from `sensitive_config`
///   reg_record      – `opaque_registration_record` bytes from the `users` table,
///                     or `None` if the user does not exist.  Passing `None` causes
///                     opaque-ke to generate a fake-but-plausible credential response
///                     that will fail MAC verification at finish — this prevents
///                     user-enumeration timing attacks (same role as bcrypt dummy hash).
///   login_start     – `CredentialRequest` bytes sent by the client
///   username        – raw username bytes (used as client identifier)
///
/// Returns `(login_response, server_login_state)`:
///   login_response    – `CredentialResponse` bytes to send to the client
///   server_login_state – bincode-serialized `ServerLogin` state; store with a
///                        60-second TTL in `opaque_login_sessions`
#[pyfunction]
fn server_start_login(
    py: Python<'_>,
    server_setup: &[u8],
    reg_record: Option<Vec<u8>>,
    login_start: &[u8],
    username: &[u8],
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let server_setup = server_setup.to_vec();
    let login_start = login_start.to_vec();
    let username = username.to_vec();

    py.allow_threads(move || {
        let mut rng = OsRng;
        let setup = ServerSetup::<TusShareCipherSuite>::deserialize(&server_setup)
            .map_err(proto_err)?;
        let maybe_record = reg_record
            .as_deref()
            .map(|b| ServerRegistration::<TusShareCipherSuite>::deserialize(b))
            .transpose()
            .map_err(proto_err)?;
        let request = CredentialRequest::<TusShareCipherSuite>::deserialize(&login_start)
            .map_err(proto_err)?;
        let params = ServerLoginParameters {
            identifiers: identifiers(&username),
            context: None,
        };
        let result = ServerLogin::<TusShareCipherSuite>::start(
            &mut rng,
            &setup,
            maybe_record,
            request,
            &username,
            params,
        )
        .map_err(proto_err)?;

        let login_response = result.message.serialize().to_vec();
        let server_state = bincode::serialize(&result.state).map_err(bincode_err)?;
        Ok((login_response, server_state))
    })
}

/// Login round 2 (server side).
///
/// Args:
///   server_login_state – bincode-serialized state returned by `server_start_login`
///   login_finish       – `CredentialFinalization` bytes sent by the client
///   username           – raw username bytes (used as client identifier)
///
/// Returns the `session_key` bytes on success, or `None` if authentication
/// fails (wrong password or MAC mismatch).  The `session_key` is 64 bytes
/// (SHA-512 output).  Both the server and client derive the identical value;
/// use it as the HMAC root for the step-up verifier.
///
/// The caller MUST delete the `opaque_login_sessions` row atomically on call
/// (consume-once semantics) to prevent replay.
#[pyfunction]
fn server_finish_login(
    py: Python<'_>,
    server_login_state: &[u8],
    login_finish: &[u8],
    username: &[u8],
) -> PyResult<Option<Vec<u8>>> {
    let server_login_state = server_login_state.to_vec();
    let login_finish = login_finish.to_vec();
    let username = username.to_vec();

    py.allow_threads(move || {
        let state: ServerLogin<TusShareCipherSuite> =
            bincode::deserialize(&server_login_state).map_err(bincode_err)?;
        let finalization = CredentialFinalization::<TusShareCipherSuite>::deserialize(&login_finish)
            .map_err(proto_err)?;
        let params = ServerLoginParameters {
            identifiers: identifiers(&username),
            context: None,
        };
        match state.finish(finalization, params) {
            Ok(result) => Ok(Some(result.session_key.to_vec())),
            // ProtocolError::InvalidLoginError is the expected "wrong password" path.
            // Any other error is also treated as auth failure — no leaking of
            // implementation details to the Python layer.
            Err(_) => Ok(None),
        }
    })
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

#[pymodule]
fn tusshare_opaque(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_server_setup, m)?)?;
    m.add_function(wrap_pyfunction!(server_start_registration, m)?)?;
    m.add_function(wrap_pyfunction!(server_finish_registration, m)?)?;
    m.add_function(wrap_pyfunction!(server_start_login, m)?)?;
    m.add_function(wrap_pyfunction!(server_finish_login, m)?)?;
    Ok(())
}
