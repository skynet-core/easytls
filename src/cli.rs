use crate::handlers::generate::{RootCAParams, UsagePolicy, algo};
use clap::builder::TypedValueParser;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Debug, Parser)]
pub struct GlobalCommonArgs {
    #[arg(
        short,
        long,
        global = true,
        help = "working directory",
        default_value = "./",
        value_name = "DIR",
        value_hint = clap::ValueHint::DirPath,
    )]
    pub workdir: PathBuf,
    #[arg(
        short,
        long,
        global = true,
        help = "output directory",
        default_value = "./",
        value_name = "DIR",
        value_hint = clap::ValueHint::DirPath,
    )]
    pub outdir: PathBuf,
    #[arg(
        short,
        long,
        global = true,
        default_value = None,
        value_parser = humantime::parse_duration,
        help = "expiration time",
        value_name = "DURATION",
    )]
    pub expires: Option<std::time::Duration>,
    #[arg(
        long,
        global = true,
        default_value = "ed25519",
        value_parser = clap::builder::PossibleValuesParser::new([
            algo::ED25519,
            algo::ECDSA_SHA384,
            algo::ECDSA_SHA256,
            algo::RSA_SHA256,
            algo::RSA_SHA384,
            algo::RSA_SHA512,
        ]),
        help = "private key algorithm",
        value_name = "STRING",
    )]
    pub algorithm: String,
    #[arg(
        long,
        global = true,
        default_value_t = 4096,
        value_parser = clap::builder::PossibleValuesParser::new(["1024", "2048", "4096", "8192"])
            .map(|s| s.parse::<usize>().unwrap()),
        help = "private key algorithm",
        value_name = "NUMBER",
    )]
    pub key_size: usize,
    #[arg(
        long,
        global = true,
        default_value = "EasyTLS",
        help = "organization's name",
        value_name = "STRING"
    )]
    pub org: String,
    #[arg(
        long,
        global = true,
        default_value = "US",
        help = "country name's code",
        value_name = "STRING"
    )]
    pub country: String,
    #[arg(
        long,
        global = true,
        default_value = "NY",
        help = "state's code",
        value_name = "STRING"
    )]
    pub state: String,
    #[arg(
        long,
        global = true,
        default_value = "localhost",
        value_parser = parsers::parse_vec_str,
        help = "hostnames to put into subject alternative names",
        value_name = "[STRING]"
    )]
    pub alt_names: std::vec::Vec<String>,
}

#[derive(Debug, Parser)]
#[command(version, about = "tls certificate generator", long_about = None)]
#[command(next_line_help = true)]
pub struct Cli {
    #[clap(flatten)]
    pub shared: GlobalCommonArgs,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "generate tls certificate")]
    Generate {
        #[command(subcommand)]
        command: Targets,
    },
}
#[derive(Debug, Parser)]
pub struct TargetCommonArgs<const N: usize = 0> {
    #[arg(
        short,
        long,
        default_value = targets::default_value::<N>(),
        help = "output file's name",
        value_name = "STRING"
    )]
    pub name: String,
}

#[derive(Debug, Parser)]
pub struct CAParams {
    #[arg(
        long,
        help = "root CA's private key file",
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
    )]
    pub ca_key: PathBuf,
    #[arg(
        long,
        help = "root CA's certificate file",
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
    )]
    pub ca_cert: PathBuf,
}

impl CAParams {
    fn as_ca_params(&self) -> RootCAParams {
        RootCAParams {
            ca_key: self.ca_key.as_path(),
            ca_cert: self.ca_cert.as_path(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Targets {
    Client {
        #[clap(flatten)]
        shared: TargetCommonArgs<{ targets::CLIENT }>,
        #[clap(flatten)]
        ca_params: CAParams,
    },
    Server {
        #[clap(flatten)]
        shared: TargetCommonArgs<{ targets::SERVER }>,
        #[clap(flatten)]
        ca_params: CAParams,
    },
    RootCA {
        #[clap(flatten)]
        shared: TargetCommonArgs<{ targets::ROOT_CA }>,
    },
}
impl Targets {
    pub fn as_usage_policy(&self) -> UsagePolicy {
        match self {
            Targets::Client { .. } => UsagePolicy::Client,
            Targets::Server { .. } => UsagePolicy::Server,
            Targets::RootCA { .. } => UsagePolicy::RootCA,
        }
    }

    pub fn target_name(&self) -> &str {
        match self {
            Targets::Client {
                shared,
                ca_params: _,
            } => &shared.name,
            Targets::Server {
                shared,
                ca_params: _,
            } => &shared.name,
            Targets::RootCA { shared } => &shared.name,
        }
    }

    pub fn ca_params(&self) -> Option<RootCAParams> {
        match self {
            Targets::Client {
                shared: _,
                ca_params,
            } => Some(ca_params.as_ca_params()),
            Targets::Server {
                shared: _,
                ca_params,
            } => Some(ca_params.as_ca_params()),
            Targets::RootCA { shared: _ } => None,
        }
    }
}

mod targets {
    pub(crate) const ROOT_CA: usize = 0;
    pub(crate) const SERVER: usize = 1;
    pub(crate) const CLIENT: usize = 2;

    pub(crate) fn default_value<const N: usize>() -> clap::builder::OsStr {
        match N {
            ROOT_CA => clap::builder::OsStr::from("rootCA"),
            SERVER => clap::builder::OsStr::from("server"),
            CLIENT => clap::builder::OsStr::from("client"),
            _ => unreachable!(),
        }
    }
}

mod parsers {
    pub(crate) fn parse_vec_str(ss: &str) -> Result<Vec<String>, String> {
        Ok(ss.split(',').map(|s| s.to_owned()).collect())
    }
}
