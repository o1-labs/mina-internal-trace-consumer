// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0
use crate::{log_entry::LogEntry, utils};
use anyhow::Result;
use mina_sdk::itn::{ItnClient, ItnKey, ItnLog};
use std::{fs::File, io::Write, path::PathBuf};
use tracing::info;

pub(crate) struct MinaServerConfig {
    /// The node's ITN GraphQL endpoint, `http://<ip>:<port>/graphql`.
    pub(crate) itn_uri: String,
    pub(crate) key: ItnKey,
    pub(crate) output_dir_path: PathBuf,
}

pub(crate) struct MinaServer {
    pub(crate) itn_client: ItnClient,
    /// The ID of the next log to fetch; `internalLogs(startLogId)` includes
    /// `startLogId` itself.
    pub(crate) next_log_id: i64,
    pub(crate) output_dir_path: PathBuf,
    pub(crate) main_trace_file: Option<File>,
    pub(crate) verifier_trace_file: Option<File>,
    pub(crate) prover_trace_file: Option<File>,
}

impl MinaServer {
    pub fn new(config: MinaServerConfig) -> Self {
        std::fs::create_dir_all(&config.output_dir_path).expect("Could not create output dir");

        Self {
            itn_client: ItnClient::new(&config.itn_uri, config.key),
            next_log_id: 0,
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

    pub(crate) fn save_log_entries(&mut self, internal_logs: Vec<ItnLog>) -> Result<()> {
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

    /// Fetch the logs from `next_log_id` on, and move `next_log_id` past
    /// the last one.
    pub(crate) async fn fetch_more_logs(&mut self) -> mina_sdk::Result<Vec<ItnLog>> {
        let logs = self.itn_client.internal_logs(self.next_log_id).await?;
        if let Some(last) = logs.last() {
            self.next_log_id = last.id + 1;
        }
        info!(
            "Fetched {} logs from {}, next log ID {}",
            logs.len(),
            self.itn_client.graphql_uri(),
            self.next_log_id
        );
        Ok(logs)
    }

    pub async fn authorize_and_run_fetch_loop(&mut self) -> Result<()> {
        // Authorize first
        self.itn_client.auth().await?;

        let mut remaining_retries = 5;

        loop {
            match self.fetch_more_logs().await {
                Ok(logs) => {
                    self.save_log_entries(logs)?;
                    remaining_retries = 5;
                }
                Err(error) => {
                    eprintln!("Error when fetching logs {error}");
                    remaining_retries -= 1;

                    if remaining_retries <= 0 {
                        eprintln!("Finishing fetcher loop");
                        return Err(error.into());
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
