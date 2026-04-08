// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0
use crate::authentication::{Authenticator, BasicAuthenticator, SequentialAuthenticator};
use crate::graphql;
use crate::graphql::internal_logs_query::InternalLogsQueryInternalLogs;
use crate::{log_entry::LogEntry, utils};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use graphql_client::GraphQLQuery;
use std::{fs::File, io::Write, path::PathBuf};
use tracing::info;

#[derive(Default, Clone)]
pub(crate) struct AuthorizationInfo {
    pub(crate) server_uuid: String,
    pub(crate) signer_sequence_number: u16,
}

pub(crate) struct MinaServerConfig {
    pub(crate) address: String,
    pub(crate) graphql_port: u16,
    pub(crate) use_https: bool,
    pub(crate) secret_key_base64: String,
    pub(crate) output_dir_path: PathBuf,
}

pub(crate) struct MinaServer {
    pub(crate) graphql_uri: String,
    pub(crate) keypair: ed25519_dalek::Keypair,
    pub(crate) pk_base64: String,
    pub(crate) last_log_id: i64,
    pub(crate) authorization_info: Option<AuthorizationInfo>,
    pub(crate) output_dir_path: PathBuf,
    pub(crate) main_trace_file: Option<File>,
    pub(crate) verifier_trace_file: Option<File>,
    pub(crate) prover_trace_file: Option<File>,
    sdk_client: mina_sdk::MinaClient,
}

impl MinaServer {
    pub fn new(config: MinaServerConfig) -> Self {
        std::fs::create_dir_all(&config.output_dir_path).expect("Could not create output dir");

        let schema = if config.use_https { "https" } else { "http" };
        let graphql_uri = format!("{}://{}:{}/graphql", schema, config.address, config.graphql_port);

        let sk_bytes = general_purpose::STANDARD
            .decode(config.secret_key_base64.trim_end())
            .expect("Failed to decode base64 secret key");
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&sk_bytes)
            .expect("Failed to interpret secret key bytes");
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        let keypair = ed25519_dalek::Keypair {
            secret: secret_key,
            public: public_key,
        };
        let pk_base64 = general_purpose::STANDARD.encode(keypair.public.as_bytes());
        let sdk_client = mina_sdk::MinaClient::new(&graphql_uri);

        Self {
            graphql_uri,
            keypair,
            pk_base64,
            last_log_id: 0,
            authorization_info: None,
            output_dir_path: config.output_dir_path,
            main_trace_file: None,
            verifier_trace_file: None,
            prover_trace_file: None,
            sdk_client,
        }
    }

    /// Get a reference to the standard Mina daemon SDK client.
    ///
    /// Use this for standard daemon queries (sync status, accounts, blocks, etc.)
    /// that don't require ITN authentication.
    pub fn daemon_client(&self) -> &mina_sdk::MinaClient {
        &self.sdk_client
    }

    // -- ITN authenticated GraphQL operations --

    pub async fn authorize(&mut self) -> Result<()> {
        let auth = self.perform_auth_query().await?;
        self.authorization_info = Some(AuthorizationInfo {
            server_uuid: auth.server_uuid,
            signer_sequence_number: auth.signer_sequence_number.parse()?,
        });
        Ok(())
    }

    pub async fn fetch_more_logs(&mut self) -> Result<(bool, Vec<InternalLogsQueryInternalLogs>)> {
        info!("Fetching more logs from {}...", self.graphql_uri);
        let prev_last_log_id = self.last_log_id;
        let (last_log_id, logs) = self.perform_fetch_internal_logs_query().await?;
        self.last_log_id = last_log_id;
        if let Some(auth_info) = &mut self.authorization_info {
            auth_info.signer_sequence_number += 1;
        }
        info!(
            "Fetched {} logs, last_log_id updated from {} to {}",
            logs.len(),
            prev_last_log_id,
            self.last_log_id
        );
        Ok((prev_last_log_id < self.last_log_id, logs))
    }

    async fn post_graphql<Q: GraphQLQuery, A: Authenticator>(
        &self,
        client: &reqwest::Client,
        variables: Q::Variables,
    ) -> Result<graphql_client::Response<Q::ResponseData>> {
        let body = Q::build_query(variables);
        let body_bytes = serde_json::to_vec(&body)?;
        let signature_header = A::signature_header(self, &body_bytes)?;
        let response = client
            .post(&self.graphql_uri)
            .json(&body)
            .header(reqwest::header::AUTHORIZATION, signature_header)
            .send()
            .await?;

        tracing::debug!("GraphQL response: {:#?}", response);

        Ok(response.json().await?)
    }

    async fn perform_auth_query(&self) -> Result<graphql::auth_query::AuthQueryAuth> {
        let client = reqwest::Client::new();
        let variables = graphql::auth_query::Variables {};
        let response = self
            .post_graphql::<graphql::AuthQuery, BasicAuthenticator>(&client, variables)
            .await?;
        let auth = response
            .data
            .ok_or_else(|| anyhow!("Response data is missing"))?
            .auth;
        Ok(auth)
    }

    async fn perform_fetch_internal_logs_query(
        &mut self,
    ) -> Result<(i64, Vec<InternalLogsQueryInternalLogs>)> {
        let client = reqwest::Client::new();
        let variables = graphql::internal_logs_query::Variables {
            log_id: self.last_log_id,
        };
        let response = self
            .post_graphql::<graphql::InternalLogsQuery, SequentialAuthenticator>(&client, variables)
            .await?;
        let response_data = response
            .data
            .ok_or_else(|| anyhow!("Response data is missing"))?;

        let mut last_log_id = self.last_log_id;

        if let Some(last) = response_data.internal_logs.last() {
            last_log_id = last.id;
        }

        Ok((last_log_id, response_data.internal_logs))
    }

    // -- Log file management --

    pub(crate) fn save_log_entries(
        &mut self,
        internal_logs: Vec<InternalLogsQueryInternalLogs>,
    ) -> Result<()> {
        for item in internal_logs {
            if let Some(log_file_handle) = self.file_for_process(&item.process)? {
                let log = LogEntry::try_from(item).unwrap();
                let log_json =
                    serde_json::to_string(&log).expect("Failed to serialize LogEntry as JSON");
                log_file_handle.write_all(log_json.as_bytes()).unwrap();
                log_file_handle.write_all(b"\n").unwrap();
            }
        }

        Ok(())
    }

    pub async fn authorize_and_run_fetch_loop(&mut self) -> Result<()> {
        // Authorize first
        self.authorize().await?;

        let mut remaining_retries = 5;

        loop {
            match self.fetch_more_logs().await {
                Ok((true, logs)) => {
                    self.save_log_entries(logs)?;
                    remaining_retries = 5;
                }
                Ok((false, logs)) => {
                    self.save_log_entries(logs)?;
                    remaining_retries = 5;
                }
                Err(error) => {
                    eprintln!("Error when fetching logs {error}");
                    remaining_retries -= 1;

                    if remaining_retries <= 0 {
                        eprintln!("Finishing fetcher loop");
                        return Err(error);
                    }
                }
            }

            let fetch_interval_ms = std::env::var("FETCH_INTERVAL_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(10000);

            tokio::time::sleep(std::time::Duration::from_millis(fetch_interval_ms)).await;
        }
    }

    pub(crate) fn file_for_process(
        &mut self,
        process: &Option<String>,
    ) -> Result<Option<&mut File>> {
        let file = match process.as_deref() {
            None => utils::maybe_open(
                &mut self.main_trace_file,
                self.output_dir_path
                    .join(crate::trace_consumer::internal_trace_file::MAIN),
            )?,
            Some("prover") => utils::maybe_open(
                &mut self.prover_trace_file,
                self.output_dir_path
                    .join(crate::trace_consumer::internal_trace_file::PROVER),
            )?,
            Some("verifier") => utils::maybe_open(
                &mut self.verifier_trace_file,
                self.output_dir_path
                    .join(crate::trace_consumer::internal_trace_file::VERIFIER),
            )?,
            Some(process) => {
                eprintln!("[WARN] got unexpected process {process}");
                return Ok(None);
            }
        };

        Ok(Some(file))
    }
}
