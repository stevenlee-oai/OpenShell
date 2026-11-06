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
    let credentials = [(
        "broker".to_owned(),
        BearerTokenSlot::new("supervisor-identity", i64::MAX).unwrap(),
    )]
    .into_iter()
    .collect();
    let registry = MiddlewareRegistry::connect_services_authenticated(
        vec![],
        vec![proto::SupervisorMiddlewareService {
            name: "broker".into(),
            grpc_endpoint: format!("https://localhost:{}", addr.port()),
            audience: "test-broker".into(),
            tls_ca_cert_pem: pem.into_bytes(),
            max_payload_bytes: 65536,
            allow_insecure_transport: false,
            binding_policy: proto::SupervisorMiddlewareBindingPolicy::Exact.into(),
            bindings: vec![
                proto::SupervisorMiddlewareBinding::HttpRequestCredentialInjection.into(),
            ],
            ..Default::default()
        }],
        &credentials,
    )
    .await
    .unwrap();
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
        app.write_all(format!("GET {path} HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer workload-value\r\nCookie: session=workload\r\n\r\n").as_bytes()).await.unwrap();
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
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        }
        let mut bytes = [0; 128];
        let n = app.read(&mut bytes).await.unwrap();
        assert_eq!(bytes[..n].starts_with(b"HTTP/1.1 200"), permitted);
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
