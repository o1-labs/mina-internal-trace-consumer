mod worker;

pub use worker::Worker as TraceConsumerWorker;

pub mod internal_trace_file {
    pub const MAIN: &str = "internal-trace.jsonl";
    pub const VERIFIER: &str = "verifier-internal-trace.jsonl";
    pub const PROVER: &str = "prover-internal-trace.jsonl";

    pub const ALL: [&str; 3] = [MAIN, VERIFIER, PROVER];
}
