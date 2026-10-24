# aien-probe

Probe evaluation engine, one of the reference crates in [aien-protocols](../../README.md).

## What it is

`aien-probe` asks questions about a piece of state without generating text. A caller supplies a JSON state and a set of typed probes. Each probe asks one question about that state:

- `Noul`: a yes or no question, answered by a probability.
- `Score`: a judgment on an ordered scale with a description for each level.
- `Choice`: a pick of one option out of a set.

Every probe is evaluated against the same state. A backend produces the answers.

## Backends

| Backend | Network | Model | Use |
| --- | --- | --- | --- |
| `DeterministicReferenceBackend` | No | No | Fixed answers for tests |
| `HttpProbeBackend` | Yes | Whatever serves the endpoint | Judgments from a model server |

`DeterministicReferenceBackend` turns a SHA-256 hash of the canonical state and the question label into a logit (a raw score before it is turned into a probability), then applies the same calibration math as the HTTP path. The same state and probes always give the same answers. It is a test oracle, not a trained model.

`HttpProbeBackend` sends `POST <endpoint>/v1/probe` with `{ "state": ..., "probes": ... }` and reads the answers back. The server side is not in this repository. On 2026-10-19 a search of [aien-sovereign-core-mv](https://github.com/aien-dev/aien-sovereign-core-mv) `main` found the `/v1/probe` route only in a client test (`crates/aien-localhttp/tests/behavior.rs`), so no AIEN server for this route was found.

## Usage

A complete program. It needs `aien-probe`, `serde_json` and `tokio` (with the `macros` and `rt-multi-thread` features) as dependencies.

```rust
use aien_probe::{DeterministicReferenceBackend, Noul, Probe, ProbeEngine, ProbeSet, Score};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
    let probes = ProbeSet::new()
        .with(
            "telemetry",
            Probe::Noul(Noul::new("Does this patch add network telemetry?")),
        )
        .with(
            "quality",
            Probe::Score(Score::new(
                "Rate the architectural quality.",
                ["unacceptable", "needs_rework", "acceptable", "exemplary"],
            )),
        );

    let response = engine.evaluate(&json!({"diff": "..."}), &probes).await?;
    println!(
        "telemetry probability {:.4}",
        response.noul("telemetry").unwrap().noul
    );
    println!("quality score {:.2}", response.score("quality").unwrap().score);
    Ok(())
}
```

On 2026-10-19 this program, built against `main` at `fb5fca9` on the Spark, printed:

```text
telemetry probability 0.1005
quality score 1.97
```

## Evaluator protocol

`ProbeEvaluator` implements the `Evaluator` trait from `aien-evaluation-protocol`, so a probe set with gates (`ProbeGate`) can run inside the `CanaryRollbackHarness` from that crate. A gate says which answers must hold for a subject to pass. A violated gate becomes a fatal finding and, in the harness, triggers rollback. `tests/probe_engine_tests.rs` covers this path.

## Test

From the repository root:

```bash
cargo test -p aien-probe
```

## License

Apache-2.0 (from `Cargo.toml`; full text in [LICENSE-CODE](../../LICENSE-CODE)).
