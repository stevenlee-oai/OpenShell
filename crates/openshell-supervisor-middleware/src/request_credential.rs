// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, HttpHeader, HttpRequestInput, HttpRequestTarget,
    HttpRequestView, MiddlewareDispatch, OnError, RequestContext, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, request_view_to_evaluation, validate_request_view,
};
use miette::{Result, miette};

impl DescribedChainEntry {
    /// Resolve over the authenticated registration. Conditions specific to the protected
    /// origin remain the authority's responsibility; a reply only authorizes this send.
    pub async fn resolve_credential(
        &self,
        input: HttpRequestInput,
    ) -> Result<(Option<String>, std::time::SystemTime)> {
        let Some(MiddlewareDispatch::Grpc(service)) = self.service.as_ref().map(|s| &s.service)
        else {
            return Err(miette!(
                "request credential needs an authenticated operator registration"
            ));
        };
        let context = RequestContext {
            request_id: input.request_id,
            sandbox_id: input.sandbox_id,
            sandbox: input.sandbox_name,
            workspace: input.workspace,
            originating_process: None,
        };
        let target = HttpRequestTarget {
            method: input.method,
            scheme: input.scheme,
            host: input.host,
            port: u32::from(input.port),
            path: input.path,
            query: input.query,
        };
        let headers: Vec<_> = input
            .headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect();
        let view = HttpRequestView::new(
            SupervisorMiddlewarePhase::CredentialInjection,
            &context,
            &self.entry.config,
            &target,
            &headers,
            &input.body,
            &self.entry.implementation,
        );
        validate_request_view(view).map_err(|_| miette!("invalid request credential envelope"))?;
        let local_deadline = std::time::SystemTime::now() + self.timeout;
        let reply = tokio::time::timeout(
            self.timeout,
            service.resolve_http_credential(request_view_to_evaluation(view)),
        )
        .await
        .map_err(|_| miette!("request credential timed out"))?
        .map_err(|_| miette!("request credential refused"))?
        .into_inner();
        let expires_at = reply
            .expires_at
            .and_then(|expiry| std::time::SystemTime::try_from(expiry).ok())
            .map(|expiry| expiry.min(local_deadline))
            .filter(|expiry| expiry > &std::time::SystemTime::now())
            .ok_or_else(|| miette!("request credential expired"))?;
        if reply.request_id != context.request_id {
            return Err(miette!(
                "request credential reply belongs to another request"
            ));
        }
        use openshell_core::proto::http_request_credential_result::Credential;
        let token = match reply.credential {
            Some(Credential::BearerToken(token)) => {
                let payload = token.trim_end_matches('=');
                if token.len() > 16 * 1024
                    || payload.is_empty()
                    || !payload
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
                {
                    return Err(miette!("invalid request bearer"));
                }
                Some(token)
            }
            Some(Credential::SendWithoutCredential(true)) => None,
            _ => {
                return Err(miette!(
                    "request credential reply lacks an authorization decision"
                ));
            }
        };
        Ok((token, expires_at))
    }
}

impl ChainRunner {
    /// Only one explicitly authorized credential service may supply a bearer to a dispatch.
    pub async fn request_credential(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Option<DescribedChainEntry>> {
        if entries.is_empty() {
            return Ok(None);
        }
        let chain = self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::HttpRequestCredential,
                SupervisorMiddlewarePhase::CredentialInjection,
            )
            .await?;
        let mut matches = chain
            .entries
            .into_iter()
            .filter(|entry| entry.binding.is_some());
        let Some(entry) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() || entry.on_error() != OnError::FailClosed {
            return Err(miette!(
                "request credential injection requires one fail-closed binding"
            ));
        }
        Ok(Some(entry))
    }
}
