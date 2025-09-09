// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0
use crate::{log_entry::LogEntry, utils};
use anyhow::Result;
use mina_graphql_client::{InternalLogsQueryInternalLogs, MinaClientConfig, MinaGraphQLClient};
use std::{fs::File, io::Write, path::PathBuf};

pub(crate) struct MinaServerConfig {
    pub(crate) client_config: MinaClientConfig,
    pub(crate) output_dir_path: PathBuf,
}

pub(crate) struct MinaServer {
    pub(crate) mina_graphql_client: MinaGraphQLClient,
    pub(crate) output_dir_path: PathBuf,
    pub(crate) main_trace_file: Option<File>,
    pub(crate) verifier_trace_file: Option<File>,
    pub(crate) prover_trace_file: Option<File>,
}

impl MinaServer {
    pub fn new(config: MinaServerConfig) -> Self {
        std::fs::create_dir_all(&config.output_dir_path).expect("Could not create output dir");

        Self {
            mina_graphql_client: MinaGraphQLClient::from(config.client_config),
            output_dir_path: config.output_dir_path,
            // TODO: this should probably be opened as soon as this instance is created and not when log entries are obtained
            // The reason is that the trace consumer expects all the files to be there, and will produce noisy warnings when
            // one is missing. Currently for some reason the graphql endpoint doesn't send some of the prover logs that
            // are present in the tracing files of non-producer nodes, so that causes the prover trace file to be missing here.
            main_trace_file: None,
            verifier_trace_file: None,
            prover_trace_file: None,
        }
    }

    pub(crate) fn save_log_entries(
        &mut self,
        internal_logs: Vec<InternalLogsQueryInternalLogs>,
    ) -> Result<()> {
        for item in internal_logs {
            if let Some(log_file_handle) = self.file_for_process(&item.process)? {
                let log = LogEntry::try_from(item).unwrap();
                let log_json =
                    serde_json::to_string(&log).expect("Failed to serialize LogEntry as JSON");
                // TODO: loging
                // println!("Log entries saved");
                // println!("{log_json}");
                log_file_handle.write_all(log_json.as_bytes()).unwrap();
                log_file_handle.write_all(b"\n").unwrap();
            }
        }

        Ok(())
    }

    pub async fn authorize_and_run_fetch_loop(&mut self) -> Result<()> {
        // Authorize first
        self.mina_graphql_client.authorize().await?;

        let mut remaining_retries = 5;

        loop {
            match self.mina_graphql_client.fetch_more_logs().await {
                Ok((true, logs)) => {
                    // Process the fetched logs using save_log_entries
                    self.save_log_entries(logs)?;
                    remaining_retries = 5;
                }
                Ok((false, logs)) => {
                    // Process logs even when no new logs were found (empty vector)
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
