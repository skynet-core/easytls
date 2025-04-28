mod cli;
mod handlers;

use clap::Parser;
use cli::{Cli, Commands};
use handlers::generate;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let parsed_args = Cli::parse();
    match parsed_args.command {
        Commands::Generate { command } => generate::handle(
            generate::GenerateParams {
                working_directory: &parsed_args.shared.workdir,
                output_directory: &parsed_args.shared.outdir,
                expires_in: parsed_args.shared.expires,
                target_name: command.target_name(),
                key_algorithm: &parsed_args.shared.algorithm,
                key_size: parsed_args.shared.key_size,
                organization: &parsed_args.shared.org,
                state: &parsed_args.shared.state,
                country: &parsed_args.shared.country,
                subject_alt_names: &parsed_args.shared.alt_names,
            },
            command.as_usage_policy(),
            command.ca_params(),
        ),
    }
}
