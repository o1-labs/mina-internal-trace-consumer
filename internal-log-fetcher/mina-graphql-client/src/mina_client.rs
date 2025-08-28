use crate::authentication::{Authenticator, BasicAuthenticator, SequentialAuthenticator};
use crate::graphql;
use crate::graphql::schedule_zkapp_commands_query::ZkappCommandsDetails;
use crate::InternalLogsQueryInternalLogs;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use graphql_client::GraphQLQuery;
use std::convert::From;
use tracing::info;

#[derive(Default, Clone)]
pub struct AuthorizationInfo {
    pub(crate) server_uuid: String,
    pub(crate) signer_sequence_number: u16,
}

pub struct MinaClientConfig {
    pub address: String,
    pub graphql_port: u16,
    pub use_https: bool,
    pub secret_key_base64: String,
}

impl MinaClientConfig {
    pub fn graphql_uri(&self) -> String {
        let schema = if self.use_https { "https" } else { "http" };
        format!(
            "{}://{}:{}/graphql",
            schema, self.address, self.graphql_port
        )
    }
}

pub struct MinaGraphQLClient {
    pub(crate) config: MinaClientConfig,
    pub(crate) keypair: ed25519_dalek::Keypair,
    pub(crate) pk_base64: String,
    pub(crate) last_log_id: i64,
    pub(crate) authorization_info: Option<AuthorizationInfo>,
}

impl From<MinaClientConfig> for MinaGraphQLClient {
    fn from(config: MinaClientConfig) -> Self {
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
        Self {
            config,
            keypair,
            pk_base64,
            last_log_id: 0,
            authorization_info: None,
        }
    }
}

impl MinaGraphQLClient {
    pub async fn authorize(&mut self) -> Result<()> {
        let auth = self.perform_auth_query().await?;
        self.authorization_info = Some(AuthorizationInfo {
            server_uuid: auth.server_uuid,
            signer_sequence_number: auth.signer_sequence_number.parse()?,
        });
        Ok(())
    }

    pub async fn fetch_more_logs(&mut self) -> Result<(bool, Vec<InternalLogsQueryInternalLogs>)> {
        info!("Fetching more logs from {}...", self.config.address);
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

    pub async fn flush_logs(&mut self) -> Result<()> {
        self.perform_flush_internal_logs_query().await?;
        if let Some(auth_info) = &mut self.authorization_info {
            auth_info.signer_sequence_number += 1;
        }

        Ok(())
    }

    pub async fn run_query_unsafe(&self, query: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let body_bytes =
            serde_json::to_vec(query).map_err(|e| anyhow!("Invalid JSON query: {}", e))?;
        let signature_header = SequentialAuthenticator::signature_header(self, &body_bytes)?;
        let response = client
            .post(&self.config.graphql_uri())
            .json(&query)
            .header(reqwest::header::AUTHORIZATION, signature_header)
            .header(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            )
            .send()
            .await?;

        Ok(response.text().await?)
    }

    pub fn get_signature(&self, body: &str) -> Result<String> {
        let body_bytes = serde_json::to_vec(body)?;
        let signature_header = SequentialAuthenticator::signature_header(self, &body_bytes)?;
        Ok(signature_header)
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
            .post(&self.config.graphql_uri())
            .json(&body)
            .header(reqwest::header::AUTHORIZATION, signature_header)
            .send()
            .await?;

        tracing::debug!("GraphQL response: {:#?}", response);

        Ok(response.json().await?)
    }

    pub async fn reset_zkapp_soft_limit_query(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::reset_zkapp_soft_limit_query::Variables {};
        let _response = self
            .post_graphql::<graphql::ResetZkappSoftLimitQuery, BasicAuthenticator>(
                &client, variables,
            )
            .await?;
        Ok(())
    }

    pub async fn schedule_zkapp_payments(&self, input: ZkappCommandsDetails) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::schedule_zkapp_commands_query::Variables { input };
        let _response = self
            .post_graphql::<graphql::ScheduleZkappCommandsQuery, BasicAuthenticator>(
                &client, variables,
            )
            .await?;
        Ok(())
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

    async fn perform_flush_internal_logs_query(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::flush_internal_logs_query::Variables {
            log_id: self.last_log_id,
        };
        let response = self
            .post_graphql::<graphql::FlushInternalLogsQuery, SequentialAuthenticator>(
                &client, variables,
            )
            .await?;
        let _response_data = response.data.unwrap();
        Ok(())
    }
}
