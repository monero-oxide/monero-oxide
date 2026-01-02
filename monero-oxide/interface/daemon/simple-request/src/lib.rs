#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

use core::{future::Future, time::Duration};
extern crate alloc;
use alloc::sync::Arc;
use std::io::Read as _;

use tokio::sync::Mutex;

use zeroize::Zeroizing;
use digest_auth::{WwwAuthenticateHeader, AuthContext};
use simple_request::{
  hyper::{StatusCode, header::HeaderValue, Request},
  Response, Client,
};

pub use monero_daemon_rpc::prelude;
use monero_daemon_rpc::{prelude::InterfaceError, HttpTransport, MoneroDaemon};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
enum Authentication {
  // If unauthenticated, use a single client
  Unauthenticated(Client),
  // If authenticated, use a single client which supports being locked and tracks its nonce
  // This ensures that if a nonce is requested, another caller doesn't make a request invalidating
  // it
  Authenticated {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    #[expect(clippy::type_complexity)]
    connection: Arc<Mutex<(Option<(WwwAuthenticateHeader, u64)>, Client)>>,
  },
}

/// An HTTP(S) transport to connect to a Monero daemon.
#[derive(Clone, Debug)]
pub struct SimpleRequestTransport {
  read_response_before_next_request: Arc<Mutex<()>>,
  authentication: Authentication,
  request_timeout: Duration,
}

impl SimpleRequestTransport {
  fn digest_auth_challenge(
    response: &Response,
  ) -> Result<Option<(WwwAuthenticateHeader, u64)>, InterfaceError> {
    Ok(if let Some(header) = response.headers().get("www-authenticate") {
      Some((
        digest_auth::parse(header.to_str().map_err(|_| {
          InterfaceError::InvalidInterface("www-authenticate header wasn't a string".to_owned())
        })?)
        .map_err(|_| InterfaceError::InvalidInterface("invalid digest-auth response".to_owned()))?,
        0,
      ))
    } else {
      None
    })
  }

  /// Create a new HTTP(S) RPC connection.
  ///
  /// The URL is parsed with a bespoke parser. It does not attempt to follow any specific
  /// specification, and should be used carefully accordingly. It does attempt to reasonably work
  /// with all URLs a caller would provide, and does so without a minimal amount of code (avoiding
  /// external dependencies). If your usage exhibits unexpected behavior, please open an issue to
  /// to let us know.
  ///
  /// A daemon requiring authentication may be used via including the username and password in the
  /// URL (`scheme://username:password@domain.tld`). Authentication is NOT guaranteed to be handled
  /// in constant time.
  pub async fn new(url: String) -> Result<MoneroDaemon<SimpleRequestTransport>, InterfaceError> {
    Self::with_custom_timeout(url, DEFAULT_TIMEOUT).await
  }

  /// Create a new HTTP(S) RPC connection with a custom timeout.
  ///
  /// Please refer to [`SimpleRequestTransport::new`] for more information.
  pub async fn with_custom_timeout(
    mut url: String,
    request_timeout: Duration,
  ) -> Result<MoneroDaemon<SimpleRequestTransport>, InterfaceError> {
    let authentication = if url.contains('@') {
      // Parse out the username and password
      let url_clone = Zeroizing::new(url);
      let split_url = url_clone.split('@').collect::<Vec<_>>();
      let mut userpass = split_url[0];
      url = split_url[1 ..].join("@");

      // If there was additionally a protocol string, restore that to the daemon URL
      if userpass.contains("://") {
        let split_userpass = userpass.split("://").collect::<Vec<_>>();
        if split_userpass.len() != 2 {
          Err(InterfaceError::InterfaceError(
            "invalid amount of protocol specifications".to_owned(),
          ))?;
        }
        url = split_userpass[0].to_owned() + "://" + &url;
        userpass = split_userpass[1];
      }

      let split_userpass = userpass.split(':').collect::<Vec<_>>();

      let client = Client::without_connection_pool(&url)
        .map_err(|_| InterfaceError::InterfaceError("invalid URL".to_owned()))?;
      // Obtain the initial challenge, which also somewhat validates this connection
      // TODO: We don't enforce any response size limit here yet should
      let challenge = Self::digest_auth_challenge(
        &tokio::time::timeout(
          request_timeout,
          client.request(Request::post(url.clone()).body(vec![].into()).map_err(|e| {
            InterfaceError::InterfaceError(format!("couldn't make request: {e:?}"))
          })?),
        )
        .await
        .map_err(|e| InterfaceError::InterfaceError(format!("timeout reached: {e:?}")))?
        .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")))?,
      )?;
      Authentication::Authenticated {
        username: Zeroizing::new(split_userpass[0].to_owned()),
        password: Zeroizing::new(split_userpass[1 ..].join(":")),
        connection: Arc::new(Mutex::new((challenge, client))),
      }
    } else {
      Authentication::Unauthenticated(Client::without_connection_pool(&url).map_err(|e| {
        InterfaceError::InternalError(format!("couldn't create client with connection pool: {e:?}"))
      })?)
    };

    MoneroDaemon::new(SimpleRequestTransport {
      read_response_before_next_request: Arc::new(Mutex::new(())),
      authentication,
      request_timeout,
    })
    .await
  }
}

impl SimpleRequestTransport {
  async fn inner_post(
    &self,
    route: &str,
    body: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> Result<Vec<u8>, InterfaceError> {
    /*
      The documentation for `monero-daemon-rpc` requires we receive the response _before_ we allow
      further requests to be made. Accordingly, we obtain a lock on a `Mutex` here to stop
      simultaneous requests from co-occurring.
    */
    let _read_response_before_next_request = self.read_response_before_next_request.lock().await;

    let request_fn = |uri| {
      Request::post(uri)
        .body(body.clone().into())
        .map_err(|e| InterfaceError::InterfaceError(format!("couldn't make request: {e:?}")))
    };

    let apply_response_size_limit = |request: Request<_>| -> simple_request::Request {
      let mut request = simple_request::Request::from(request);
      request.set_response_size_limit(response_size_limit);
      request
    };

    async fn body_from_response(response: Response<'_>) -> Result<Vec<u8>, InterfaceError> {
      let mut res = Vec::with_capacity(128);
      response
        .body()
        .await
        .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")))?
        .read_to_end(&mut res)
        .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")))?;
      Ok(res)
    }

    for attempt in 0 .. 2 {
      return Ok(match &self.authentication {
        Authentication::Unauthenticated(client) => {
          body_from_response(
            client
              .request(apply_response_size_limit(request_fn("/".to_owned() + route)?))
              .await
              .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")))?,
          )
          .await?
        }
        Authentication::Authenticated { username, password, connection } => {
          let mut connection_lock = connection.lock().await;

          let mut request = request_fn("/".to_owned() + route)?;

          // If we don't have an auth challenge, obtain one
          if connection_lock.0.is_none() {
            connection_lock.0 = Self::digest_auth_challenge(
              &connection_lock
                .1
                .request(apply_response_size_limit(request))
                .await
                .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")))?,
            )?;
            request = request_fn("/".to_owned() + route)?;
          }

          // Insert the challenge response, if we have a challenge
          if let Some((challenge, cnonce)) = connection_lock.0.as_mut() {
            // Update the cnonce
            // Overflow isn't a concern as this is a u64
            *cnonce += 1;

            let mut context = AuthContext::new_post::<_, _, _, &[u8]>(
              <_ as AsRef<str>>::as_ref(username),
              <_ as AsRef<str>>::as_ref(password),
              "/".to_owned() + route,
              None,
            );
            context.set_custom_cnonce(hex::encode(cnonce.to_le_bytes()));

            request.headers_mut().insert(
              "Authorization",
              HeaderValue::from_str(
                &challenge
                  .respond(&context)
                  .map_err(|_| {
                    InterfaceError::InvalidInterface(
                      "couldn't respond to digest-auth challenge".to_owned(),
                    )
                  })?
                  .to_header_string(),
              )
              .map_err(|_| {
                InterfaceError::InternalError(
                  "digest-auth challenge response wasn't a valid string for an HTTP header"
                    .to_owned(),
                )
              })?,
            );
          }

          let response = connection_lock
            .1
            .request(apply_response_size_limit(request))
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("{e:?}")));

          let (error, is_stale) = match &response {
            Err(e) => (Some(e.clone()), false),
            Ok(response) => (
              None,
              if response.status() == StatusCode::UNAUTHORIZED {
                if let Some(header) = response.headers().get("www-authenticate") {
                  header
                    .to_str()
                    .map_err(|_| {
                      InterfaceError::InvalidInterface(
                        "www-authenticate header wasn't a string".to_owned(),
                      )
                    })?
                    .contains("stale")
                } else {
                  false
                }
              } else {
                false
              },
            ),
          };

          // If the connection entered an error state, drop the cached challenge as challenges are
          // per-connection
          // We don't need to create a new connection as simple-request will for us
          if error.is_some() || is_stale {
            connection_lock.0 = None;
            // If we're not already on our second attempt, move to the next loop iteration
            // (retrying all of this once)
            if attempt == 0 {
              continue;
            }
            if let Some(e) = error {
              Err(e)?
            } else {
              debug_assert!(is_stale);
              Err(InterfaceError::InvalidInterface(
                "node claimed fresh connection had stale authentication".to_owned(),
              ))?
            }
          } else {
            body_from_response(response.expect("no response yet also no error?")).await?
          }
        }
      });
    }

    unreachable!()
  }
}

impl HttpTransport for SimpleRequestTransport {
  fn post(
    &self,
    route: &str,
    body: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
    async move {
      tokio::time::timeout(self.request_timeout, self.inner_post(route, body, response_size_limit))
        .await
        .map_err(|e| InterfaceError::InterfaceError(format!("timeout reached: {e:?}")))?
    }
  }
}
