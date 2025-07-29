// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::{fs::OpenOptions, path::PathBuf};
use tokio::process::Command;

pub struct Worker {
    consumer_executable_path: PathBuf,
    main_trace_file_path: PathBuf,
    db_uri: String,
    node_identifier: String,
    // TODO: process handle here?
}

impl Worker {
    pub fn new(
        consumer_executable_path: PathBuf,
        main_trace_file_path: PathBuf,
        db_uri: String,
        node_identifier: String,
    ) -> Self {
        Self {
            consumer_executable_path,
            main_trace_file_path,
            db_uri,
            node_identifier,
        }
    }

    pub async fn run(&mut self) -> tokio::io::Result<tokio::process::Child> {
        let base_path = self.main_trace_file_path.parent().unwrap().to_path_buf();
        let handle_status_change =
            env::var("HANDLE_STATUS_CHANGE").unwrap_or_else(|_| "false".to_string());

        let stdout_log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(base_path.join("consumer-stdout.log"))
            .unwrap();

        let stderr_log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(base_path.join("consumer-stderr.log"))
            .unwrap();

        let child = Command::new(&self.consumer_executable_path)
            .env("MINA_NODE_NAME", &self.node_identifier)
            .arg("process")
            .arg("--trace-file")
            .arg(&self.main_trace_file_path)
            .arg("--process-rotated-files")
            .arg(true.to_string())
            .arg("--db-uri")
            .arg(&self.db_uri)
            .arg("--handle-status-change")
            .arg(&handle_status_change)
            .stdout(stdout_log_file)
            .stderr(stderr_log_file)
            .kill_on_drop(true)
            .spawn()?;

        tokio::io::Result::Ok(child)
    }
}
