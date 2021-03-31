//! The hyper based HTTP client

/// The hyper specific implementation details are abstracted out in this file.
/// This is IC agnostic. The TLS specific details are also handled here.
///
/// Two interfaces are exposed:
/// - AgentStub: used by the agent.rs. The Agent has business logic that runs on
///   top of this interface
/// - RequestStub: low level API used by call sites outside Agent. We have
///   several call sites that create ad hoc hyper/reqwest clients to issue HTTP
///   requests. These don't really need/create an Agent. This interface aims to
///   provide a wrapper that allows these use cases, while also taking care of
///   the TLS requirements
use async_trait::async_trait;
use hyper::client::HttpConnector as HyperConnector;
use hyper::client::ResponseFuture as HyperFuture;
use hyper::Client as HyperClient;
use hyper::Uri as HyperUri;
use hyper_tls::HttpsConnector as HyperTlsConnector;
use std::time::Duration;
use url::Url;

/// The interface internal to the agent
#[async_trait]
pub(crate) trait AgentStub: Send + Sync {
    /// Sends a GET request and returns the response bytes
    async fn get(&self, url: &Url, end_point: &str, timeout: Duration) -> Result<Vec<u8>, String>;

    /// Sends a POST request
    async fn post(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), String>;

    /// Sends a POST request and returns the response bytes
    async fn post_with_response(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String>;
}

/// Interface to perform operations directly on the client stub.
/// This is for call sites outside the agent that don't create an agent, but
/// create ad-hoc reqwest clients to issue HTTP commands. This interface
/// provides a wrapper to perform these operations, with the required TLS
/// support.
#[async_trait]
pub trait RequestStub: Send + Sync {
    /// Sends a POST request.
    /// On success, returns Ok(HTTP response bytes, HTTP status code).
    async fn send_post_request(
        &self,
        url: &str,
        content_type: Option<HttpContentType>,
        http_body: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<(Vec<u8>, hyper::StatusCode), String>;
}

#[derive(Debug)]
pub enum HttpContentType {
    CBOR,
    JSON,
}

impl HttpContentType {
    fn as_str(&self) -> String {
        match self {
            HttpContentType::CBOR => "application/cbor".to_string(),
            HttpContentType::JSON => "application/json".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct HttpClient {
    hyper: HyperClient<HyperTlsConnector<HyperConnector>>,
}

impl HttpClient {
    pub fn new() -> Self {
        let native_tls_connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build tls connector");
        let mut http_connector = HyperConnector::new();
        http_connector.enforce_http(false);
        let https_connector =
            HyperTlsConnector::from((http_connector, native_tls_connector.into()));

        let hyper = HyperClient::builder()
            .pool_idle_timeout(Some(Duration::from_secs(600)))
            .pool_max_idle_per_host(1)
            .build::<_, hyper::Body>(https_connector);

        Self { hyper }
    }

    fn build_uri(&self, url: &Url, end_point: &str) -> Result<HyperUri, String> {
        let url = url.join(end_point).map_err(|e| {
            format!(
                "HttpClient: Failed to create URI for {}: {:?}",
                end_point, e
            )
        })?;

        url.as_str()
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse {:?}: {:?}", url, e))
    }

    fn build_post_request(&self, uri: HyperUri, http_body: Vec<u8>) -> Result<HyperFuture, String> {
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri.clone())
            .header("Content-Type", "application/cbor")
            .body(hyper::Body::from(http_body))
            .map_err(|e| {
                format!(
                    "HttpClient: Failed to create POST request for {:?}: {:?}",
                    uri, e
                )
            })?;
        Ok(self.hyper.request(req))
    }

    async fn wait_for_one_http_request(
        uri: HyperUri,
        response_future: HyperFuture,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let result = tokio::time::timeout(timeout, response_future)
            .await
            .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?;
        let response = result.map_err(|e| format!("Request failed for {:?}: {:?}", uri, e))?;
        if !response.status().is_success() {
            return Err(format!(
                "HTTP Client: Request for {:?} failed: {:?}",
                uri, response
            ));
        }
        hyper::body::to_bytes(response)
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| {
                format!(
                    "HttpClient: Request failed to get bytes for {:?}: {:?}",
                    uri, e
                )
            })
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentStub for HttpClient {
    async fn get(&self, url: &Url, end_point: &str, timeout: Duration) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        Self::wait_for_one_http_request(uri.clone(), self.hyper.get(uri), timeout).await
    }

    async fn post(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.build_post_request(uri.clone(), http_body)?;

        let result = tokio::time::timeout(timeout, response_future)
            .await
            .map_err(|e| format!("HttpClient: POST Timed out for {:?}: {:?}", uri, e))?;
        result
            .map(|_| ())
            .map_err(|e| format!("HttpClient: POST failed for {:?}: {:?}", uri, e))
    }

    async fn post_with_response(
        &self,
        url: &Url,
        end_point: &str,
        http_body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let uri = self.build_uri(url, end_point)?;
        let response_future = self.build_post_request(uri.clone(), http_body)?;
        Self::wait_for_one_http_request(uri, response_future, timeout).await
    }
}

#[async_trait]
impl RequestStub for HttpClient {
    async fn send_post_request(
        &self,
        url: &str,
        content_type: Option<HttpContentType>,
        http_body: Option<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Result<(Vec<u8>, hyper::StatusCode), String> {
        let uri = url
            .parse::<HyperUri>()
            .map_err(|e| format!("HttpClient: Failed to parse URL {:?}: {:?}", url, e))?;
        let req = hyper::Request::builder().method("POST").uri(uri.clone());
        let req = if let Some(content) = content_type {
            req.header("Content-Type", content.as_str())
        } else {
            req
        };
        let req = if let Some(body) = http_body {
            req.body(hyper::Body::from(body))
        } else {
            req.body(hyper::Body::empty())
        };
        let req = req.map_err(|e| format!("HttpClient: Failed to fill body {:?}: {:?}", url, e))?;
        let response_future = self.hyper.request(req);

        let response = if let Some(to) = timeout {
            tokio::time::timeout(to, response_future)
                .await
                .map_err(|e| format!("HttpClient: Request timed out for {:?}: {:?}", uri, e))?
        } else {
            response_future.await
        };
        let response_body = response
            .map_err(|e| format!("HttpClient: Request failed out for {:?}: {:?}", uri, e))?;
        let status_code = response_body.status();
        let response_bytes = hyper::body::to_bytes(response_body)
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|e| format!("HttpClient: Failed to get bytes for {:?}: {:?}", uri, e))?;

        Ok((response_bytes, status_code))
    }
}
