// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{L7EvalContext, relay_with_inspection};
use crate::opa::{NetworkInput, OpaEngine};
use openshell_core::extension_protocol::{
    ExtensionFamily, HTTP_REQUEST_CREDENTIAL, extension_metadata,
};
use openshell_core::proto::{
    self,
    http_request_credential_result::Credential,
    http_request_credential_server::{HttpRequestCredential, HttpRequestCredentialServer},
    supervisor_middleware_server::{SupervisorMiddleware, SupervisorMiddlewareServer},
};
use openshell_extension_core::BearerTokenSlot;
use openshell_supervisor_middleware::{ChainRunner, MiddlewareRegistry, WebSocketResponseStream};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

#[derive(Clone, Default)]
struct Broker(Arc<AtomicUsize>);

#[tonic::async_trait]
impl SupervisorMiddleware for Broker {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;
    async fn describe(
        &self,
        req: Request<proto::MiddlewareDescribeRequest>,
    ) -> Result<Response<proto::MiddlewareManifest>, Status> {
        assert!(
            req.into_inner()
                .gateway
                .unwrap()
                .supported_capabilities
                .iter()
                .any(|c| c == HTTP_REQUEST_CREDENTIAL)
        );
        Ok(Response::new(proto::MiddlewareManifest {
            name: "broker".into(),
            service_version: "1".into(),
            expected_audience: "test-broker".into(),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                "test",
                "1",
                [HTTP_REQUEST_CREDENTIAL.to_owned()],
            )),
            bindings: vec![proto::MiddlewareBinding {
                operation: proto::SupervisorMiddlewareOperation::HttpRequestCredential.into(),
                phase: proto::SupervisorMiddlewarePhase::CredentialInjection.into(),
                max_payload_bytes: 65536,
                request_timeout: None,
            }],
        }))
    }
    async fn validate_config(
        &self,
        _: Request<proto::ValidateConfigRequest>,
    ) -> Result<Response<proto::ValidateConfigResponse>, Status> {
        Ok(Response::new(proto::ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }
    async fn evaluate_http_request(
        &self,
        _: Request<proto::HttpRequestEvaluation>,
    ) -> Result<Response<proto::HttpRequestResult>, Status> {
        Err(Status::unimplemented("dedicated credential binding"))
    }
    async fn evaluate_web_socket_session(
        &self,
        _: Request<tonic::Streaming<proto::WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented("HTTP only"))
    }
}

#[tonic::async_trait]
impl HttpRequestCredential for Broker {
    async fn resolve(
        &self,
        req: Request<proto::HttpRequestEvaluation>,
    ) -> Result<Response<proto::HttpRequestCredentialResult>, Status> {
        assert_eq!(
            req.metadata().get("authorization").unwrap(),
            "Bearer supervisor-identity"
        );
        let input = req.into_inner();
        assert_eq!(
            input.phase,
            proto::SupervisorMiddlewarePhase::CredentialInjection as i32
        );
        assert!(
            input
                .headers
                .iter()
                .all(|h| h.name != "authorization" && h.name != "cookie")
        );
        assert!(!input.headers.iter().any(|h| h.name == "x-amz-target"));
        assert!(
            input
                .headers
                .iter()
                .any(|h| h.name == "x-approved-header" && h.value == "same-value")
        );
        let request_id = input.context.unwrap().request_id;
        let path = input.target.unwrap().path;
        let credential = match self.0.fetch_add(1, Ordering::SeqCst) {
            0 => Credential::BearerToken("first".into()),
            1 => Credential::BearerToken("refreshed".into()),
            2 => {
                assert_eq!(path, "/discovery/v1/apis/gmail/v1/rest");
                Credential::SendWithoutCredential(true)
            }
            _ => return Err(Status::permission_denied("grant detached")),
        };
        Ok(Response::new(proto::HttpRequestCredentialResult {
            request_id,
            credential: Some(credential),
            expires_at: Some(
                (std::time::SystemTime::now() + std::time::Duration::from_secs(2)).into(),
            ),
        }))
    }
}

#[tokio::test]
async fn terminal_authority_replaces_each_request_bearer_or_authorizes_a_public_request() {
    tokio::time::timeout(std::time::Duration::from_secs(12), exercise_broker())
        .await
        .expect("request credential exchange completed");
}
async fn exercise_broker() {
    let cert =
        openshell_crypto::pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(
        pem.as_bytes(),
        cert.key_pair.serialize_pem().unwrap().as_bytes(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = Broker::default();
    let server = tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(SupervisorMiddlewareServer::new(broker.clone()))
            .add_service(HttpRequestCredentialServer::new(broker.clone()))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let registry = authenticated_registry(
        "broker",
        format!("https://localhost:{}", addr.port()),
        pem,
        "test-broker",
        "supervisor-identity",
    )
    .await;
    let data = r"
network_middlewares:
  request-account:
    middleware: broker
    on_error: fail_closed
    endpoints: { include: [api.example.test] }
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: '/**' }
    binaries: [{ path: /usr/bin/curl }]
";
    let engine =
        OpaEngine::from_strings(include_str!("../../../data/sandbox-policy.rego"), data).unwrap();
    engine.set_middleware_runner_for_tests(ChainRunner::from_registry(registry));
    let input = NetworkInput {
        host: "api.example.test".into(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: "test".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (config, generation) = engine
        .query_endpoint_config_with_generation(&input)
        .unwrap();
    let config = crate::l7::parse_l7_config(&config.unwrap()).unwrap();
    let ctx = L7EvalContext {
        host: input.host,
        port: input.port,
        request_default_port: Some(443),
        policy_name: "api".into(),
        binary_path: "/usr/bin/curl".into(),
        ..Default::default()
    };

    for (path, expected, permitted) in [
        ("/v1/resource", Some("first"), true),
        ("/v1/resource", Some("refreshed"), true),
        ("/discovery/v1/apis/gmail/v1/rest", None, true),
        ("/v1/resource", None, false),
    ] {
        let (mut app, mut supervisor) = tokio::io::duplex(8192);
        let (mut upstream, mut origin) = tokio::io::duplex(8192);
        let cfg = config.clone();
        let context = ctx.clone();
        let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
        let relay = tokio::spawn(async move {
            relay_with_inspection(&cfg, tunnel, &mut supervisor, &mut upstream, &context).await
        });
        app.write_all(format!("GET {path} HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer workload-value\r\nCookie: session=workload\r\nX-Amz-Target: unreviewed-workload-operation\r\nX-Approved-Header: same-value\r\n\r\n").as_bytes()).await.unwrap();
        if permitted {
            let mut wire = vec![];
            while !wire.ends_with(b"\r\n\r\n") {
                let byte = origin.read_u8().await.unwrap();
                wire.push(byte);
            }
            let message = std::str::from_utf8(&wire).unwrap();
            let auth: Vec<_> = message
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.trim())
                .collect();
            assert_eq!(auth, expected.map(|t| format!("Bearer {t}")).as_slice());
            assert!(!message.contains("workload"));
            assert!(
                message
                    .to_ascii_lowercase()
                    .contains("x-approved-header: same-value")
            );
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        let mut bytes = [0; 128];
        let n = app.read(&mut bytes).await.unwrap();
        if permitted {
            assert!(bytes[..n].starts_with(b"HTTP/1.1 200"));
        } else {
            assert!(bytes[..n].starts_with(b"HTTP/1.1 403"));
        }
        drop(app);
        relay.await.unwrap().unwrap();
        if !permitted {
            assert_eq!(
                origin.read(&mut bytes).await.unwrap(),
                0,
                "denial must prevent the upstream write"
            );
        }
    }
    // These inputs reach an HTTP parser without proving a verified destination.
    // Neither may contact the broker or write a byte to the origin.
    for (port, host_header) in [
        (None, "Host: api.example.test\r\n"),
        (Some(80), "Host: api.example.test\r\n"),
        (Some(443), ""),
    ] {
        let mut context = ctx.clone();
        context.request_default_port = port;
        let (mut app, mut supervisor) = tokio::io::duplex(8192);
        let (mut upstream, mut origin) = tokio::io::duplex(8192);
        let cfg = config.clone();
        let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
        let task = tokio::spawn(async move {
            relay_with_inspection(&cfg, tunnel, &mut supervisor, &mut upstream, &context).await
        });
        app.write_all(format!("GET /v1/resource HTTP/1.0\r\n{host_header}\r\n").as_bytes())
            .await
            .unwrap();
        let mut received = [0u8; 128];
        let count = app.read(&mut received).await.unwrap();
        assert!(!received[..count].starts_with(b"HTTP/1.1 200"));
        drop(app);
        task.await.unwrap().unwrap();
        assert_eq!(origin.read(&mut received).await.unwrap(), 0);
    }
    assert_eq!(broker.0.load(Ordering::SeqCst), 4);
    server.abort();
}

async fn authenticated_registry(
    name: &str,
    url: String,
    ca_pem: String,
    audience: &str,
    supervisor_token: &str,
) -> MiddlewareRegistry {
    let credentials = std::collections::HashMap::from([(
        name.to_owned(),
        BearerTokenSlot::new(supervisor_token, i64::MAX).unwrap(),
    )]);
    MiddlewareRegistry::connect_services_authenticated(
        vec![],
        vec![proto::SupervisorMiddlewareService {
            name: name.into(),
            grpc_endpoint: url,
            audience: audience.into(),
            tls_ca_cert_pem: ca_pem.into_bytes(),
            max_payload_bytes: 65536,
            request_timeout: Some(prost_types::Duration {
                seconds: 10,
                nanos: 0,
            }),
            binding_policy: proto::SupervisorMiddlewareBindingPolicy::Exact.into(),
            bindings: vec![
                proto::SupervisorMiddlewareBinding::HttpRequestCredentialInjection.into(),
            ],
            ..Default::default()
        }],
        &credentials,
    )
    .await
    .expect("authenticate credential authority")
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalRequest {
    broker_url: String,
    broker_ca_pem: String,
    audience: String,
    supervisor_token: String,
    sandbox_id: String,
    sandbox_name: String,
    workspace: String,
    middleware_name: String,
    binding_config: serde_json::Value,
    origin_host: String,
    origin_port: u16,
    origin_address: std::net::SocketAddr,
    origin_ca_pem: String,
    path: String,
    body: serde_json::Value,
}

/// Connect an installed authority to a controlled HTTPS origin using the native inspected relay.
/// Each invocation receives a fresh sandbox identity and reports only the downstream HTTP status.
#[tokio::test]
#[ignore = "requires an external credential broker, signed supervisor identity and HTTPS origin"]
async fn external_request_credential_dispatch() {
    let path =
        std::env::var_os("OPENSHELL_TEST_BROKER_REQUEST").expect("private request fixture path");
    let file = std::fs::File::open(path).expect("open fixture");
    let meta = file.metadata().unwrap();
    assert!(
        meta.is_file() && meta.len() <= 256 * 1024,
        "expected a bounded regular request fixture"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            meta.permissions().mode() & 0o077,
            0,
            "fixture contains a supervisor credential"
        );
    }
    let input: ExternalRequest = serde_json::from_reader(file).expect("parse request fixture");
    let registry = authenticated_registry(
        &input.middleware_name,
        input.broker_url,
        input.broker_ca_pem,
        &input.audience,
        &input.supervisor_token,
    )
    .await;
    let tool = input
        .body
        .pointer("/params/name")
        .and_then(serde_json::Value::as_str)
        .expect("provide an MCP tools/call request");
    let data = serde_json::json!({
       "network_middlewares": {"broker": {"middleware":input.middleware_name, "on_error":"fail_closed", "endpoints":{"include":[input.origin_host]}, "config":input.binding_config}},
       "network_policies":{"mcp":{"name":"mcp","endpoints":[{"host":input.origin_host,"port":input.origin_port,"path":input.path,"protocol":"mcp","enforcement":"enforce","mcp":{"versions":["2025-11-25"]},"rules":[{"allow":{"method":"tools/call","tool":tool}}]}],"binaries":[{"path":"/usr/bin/node"}]}}
    });
    let engine = OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        &data.to_string(),
    )
    .unwrap();
    engine.set_middleware_runner_for_tests(ChainRunner::from_registry(registry));
    let workload = NetworkInput {
        host: input.origin_host.clone(),
        port: input.origin_port,
        binary_path: "/usr/bin/node".into(),
        binary_sha256: "fixture".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (config, generation) = engine
        .query_endpoint_config_with_generation(&workload)
        .unwrap();
    let config = crate::l7::parse_l7_config(&config.unwrap()).unwrap();
    let evaluator = engine.clone_engine_for_tunnel(generation).unwrap();
    let ctx = L7EvalContext {
        host: input.origin_host.clone(),
        port: input.origin_port,
        workspace: input.workspace,
        request_default_port: Some(443),
        binary_path: "/usr/bin/node".into(),
        policy_name: "mcp".into(),
        ..Default::default()
    };
    let context = openshell_ocsf::EventContext {
        sandbox_id: input.sandbox_id,
        sandbox_name: input.sandbox_name,
        ..(*openshell_ocsf::ctx::ctx()).clone()
    };
    openshell_ocsf::ctx::bind_thread_ctx(Some(Arc::new(context)));
    let trust = crate::l7::tls::build_upstream_client_config(&input.origin_ca_pem).unwrap();
    let tcp = tokio::net::TcpStream::connect(input.origin_address)
        .await
        .expect("connect HTTPS origin");
    let name = rustls::pki_types::ServerName::try_from(input.origin_host.clone()).unwrap();
    let mut origin = tokio_rustls::TlsConnector::from(trust)
        .connect(name, tcp)
        .await
        .expect("verify HTTPS origin");
    let (mut caller, mut client) = tokio::io::duplex(65536);
    let relay = tokio::spawn(async move {
        relay_with_inspection(&config, evaluator, &mut client, &mut origin, &ctx).await
    });
    let authority = if input.origin_port == 443 {
        input.origin_host
    } else {
        format!("{}:{}", input.origin_host, input.origin_port)
    };
    let body = input.body.to_string();
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer workload-value\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\nContent-Length: {}\r\n\r\n{body}",
        input.path,
        body.len()
    );
    caller.write_all(request.as_bytes()).await.unwrap();
    let mut status_line = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while !status_line.ends_with(b"\r\n") && status_line.len() < 512 {
            status_line.push(caller.read_u8().await.expect("downstream status"));
        }
    })
    .await
    .expect("complete downstream status");
    let status = std::str::from_utf8(&status_line)
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse::<u16>()
        .unwrap();
    println!("OPENSHELL_TEST_HTTP_STATUS={status}");
    drop(caller);
    relay.abort();
    openshell_ocsf::ctx::bind_thread_ctx(None);
}
