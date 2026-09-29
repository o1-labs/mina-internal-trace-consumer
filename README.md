# Internal trace consumer

## Build

```
opam switch create . 4.14.0
# Follow instructions given by above command to enable the environment
# with `eval $(opam env)` if necessary then continue with:
opam switch import opam.export
dune build src/internal_trace_consumer.exe
```

## Usage

```
./_build/default/src/internal_trace_consumer.exe serve \
  --trace-file /path/to/internal_trace.jsonl
```

or

```
dune exec ./src/internal_trace_consumer.exe serve \
  --trace-file /path/to/internal_trace.jsonl
```

which will rebuild the program before executing it.

This will expose a GraphQL server in `http://localhost:9080/graphql`.

## Docker images

### Building

```
docker build . -t internal-trace-consumer:latest
```

### Running

Assuming the main trace file is in `path/to/internal-traces/internal-trace.jsonl`:

```
docker run \
  -p 9080:9080 \
  -v path/to/internal-traces:/traces \
  internal-trace-consumer:latest
```

will run the internal trace consumer and expose the GraphQL server in `http://localhost:9080/graphql`.

## Internal log fetcher and the ITN debug CLI

`internal-log-fetcher/` reads each node's internal logs through the daemon's
ITN GraphQL server (`ITN_FEATURES=1`, `--itn-graphql-port`, `--itn-keys`) with
[`mina-sdk`](https://github.com/o1-labs/mina-sdk-rust) (feature `itn`), and
writes them as trace files for the consumer. Its key (`-k`) is a base64
ed25519 seed; the daemon's `--itn-keys` must list the matching public key.

The same crate builds `mina-graphql-client`, a debug CLI for the ITN server:

```sh
cd internal-log-fetcher
KEY=<base64 seed> ADDRESS=http://<node>:<itn port> \
  cargo run --bin mina-graphql-client -- --help
```

It runs `auth`, `fetch-more-logs`, `flush-logs`, `slots-won`,
`schedule-payments`, `schedule-zkapp-payments`, `stop-payments`,
`update-gating`, `reset-zkapp-soft-limit` and `stop-daemon`; `--json` prints
machine-readable output. `get-peers` and `connection-gating-config` send
unsigned public GraphQL, so for them `ADDRESS` is the node's public port
(3085 by default).
