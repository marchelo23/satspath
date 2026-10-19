use clap::{Parser, Subcommand, ValueEnum};
use satspath_conformance::{run_observed_suite, run_suite, CaseReport, CaseStatus, VectorSuite};

#[derive(Parser)]
#[command(name = "satspath-conformance")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run local vectors, compare an external SDK's results or probe an HTTPS resolver.
    Test {
        /// Defaults to the embedded v1 suite, independent of the working directory.
        #[arg(long)]
        vectors: Option<std::path::PathBuf>,
        #[arg(long)]
        observed: Option<std::path::PathBuf>,
        #[arg(long)]
        resolver: Option<String>,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() {
    let Cli { command } = Cli::parse();
    let Command::Test {
        vectors,
        observed,
        resolver,
        alias,
        format,
    } = command;
    let result: Result<(), String> = async {
        let bytes = match vectors {
            Some(path) => std::fs::read(path).map_err(|e| e.to_string())?,
            None => include_bytes!("../vectors/v1.json").to_vec(),
        };
        let suite: VectorSuite = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let mut report = if let Some(path) = observed {
            let outputs = serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            run_observed_suite(&suite, &outputs)
        } else {
            run_suite(&suite)
        };
        if let Some(url) = resolver {
            let expected = alias.ok_or("--alias is required with --resolver")?;
            let outcome = satspath_core::HttpResolver::new()
                .resolve_from_url(&url)
                .await
                .and_then(|profile| {
                    if satspath_core::canonical_identifier(&profile.profile.alias)
                        == satspath_core::canonical_identifier(&expected)
                    {
                        Ok(())
                    } else {
                        Err(satspath_core::SatsPathError::ValidationError(
                            "resolver returned a different alias".into(),
                        ))
                    }
                });
            let (status, detail) = match outcome {
                Ok(()) => {
                    report.passed += 1;
                    (CaseStatus::Pass, String::new())
                }
                Err(error) => {
                    report.failed += 1;
                    (CaseStatus::Fail, error.to_string())
                }
            };
            report.cases.push(CaseReport {
                id: "live-resolver".into(),
                kind: "resolver".into(),
                status,
                detail,
            });
        }
        match format {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            ),
            OutputFormat::Text => {
                for case in &report.cases {
                    let status = match case.status {
                        CaseStatus::Pass => "PASS",
                        CaseStatus::Fail => "FAIL",
                        CaseStatus::Skip => "SKIP",
                    };
                    println!("{} {:<30} {}", status, case.id, case.detail);
                }
                println!(
                    "SatsPath conformance: {}/{} ({} skipped)",
                    report.passed,
                    report.cases.len(),
                    report.skipped
                );
            }
        }
        if report.is_complete() {
            Ok(())
        } else {
            Err("conformance incomplete".into())
        }
    }
    .await;
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
