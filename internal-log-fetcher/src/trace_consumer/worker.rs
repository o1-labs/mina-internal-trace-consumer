// Copyright (c) Viable Systems
// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    path::{Path, PathBuf},
};
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};

const DEFAULT_LOG_ROTATION_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_LOG_ROTATION_COUNT: usize = 5;

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

    pub async fn run(&mut self) -> tokio::io::Result<Child> {
        let base_path = self.main_trace_file_path.parent().unwrap().to_path_buf();
        let handle_status_change =
            env::var("HANDLE_STATUS_CHANGE").unwrap_or_else(|_| "false".to_string());
        let log_rotation_size_bytes = env::var("CONSUMER_LOG_ROTATION_SIZE_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_LOG_ROTATION_SIZE_BYTES);
        let log_rotation_count = env::var("CONSUMER_LOG_ROTATION_COUNT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_LOG_ROTATION_COUNT);

        let mut child = Command::new(&self.consumer_executable_path)
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
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(pipe_output(
                stdout,
                base_path.join("consumer-stdout.log"),
                log_rotation_size_bytes,
                log_rotation_count,
            ));
        }

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(pipe_output(
                stderr,
                base_path.join("consumer-stderr.log"),
                log_rotation_size_bytes,
                log_rotation_count,
            ));
        }

        tokio::io::Result::Ok(child)
    }
}

async fn pipe_output<R>(
    mut reader: R,
    log_path: PathBuf,
    max_size_bytes: u64,
    rotation_count: usize,
) -> tokio::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let max_size_bytes = max_size_bytes.max(1);
    let mut file = open_log_file(&log_path).await?;
    let mut current_size = file
        .metadata()
        .await
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let mut buffer = [0_u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            file.flush().await?;
            return Ok(());
        }

        if current_size + bytes_read as u64 > max_size_bytes {
            rotate_logs(&log_path, rotation_count).await?;
            file = open_log_file(&log_path).await?;
            current_size = 0;
        }

        file.write_all(&buffer[..bytes_read]).await?;
        current_size += bytes_read as u64;
    }
}

async fn open_log_file(path: &Path) -> tokio::io::Result<tokio::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

async fn rotate_logs(path: &Path, rotation_count: usize) -> tokio::io::Result<()> {
    if rotation_count == 0 {
        let _ = tokio::fs::remove_file(path).await;
        return Ok(());
    }

    for index in (1..=rotation_count).rev() {
        let source = rotated_log_path(path, index - 1);
        let destination = rotated_log_path(path, index);
        if tokio::fs::try_exists(&source).await? {
            let _ = tokio::fs::remove_file(&destination).await;
            tokio::fs::rename(source, destination).await?;
        }
    }

    Ok(())
}

fn rotated_log_path(path: &Path, index: usize) -> PathBuf {
    if index == 0 {
        path.to_path_buf()
    } else {
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }
}
