use crate::handlers::generate::utils::{
    WorkdirHandler, save_to_file, set_distinguished_name, set_expiration, set_key_usages,
    to_ca_credentials,
};
use rcgen::{ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
use std::cmp::PartialEq;
use std::error::Error;
use std::string::ToString;
use std::time::Duration;

pub const DEFAULT_COMMON_NAME: &'static str = "localhost";

pub mod algo {
    pub const ED25519: &'static str = "ed25519";
    pub const ECDSA_SHA384: &'static str = "ecdsa-sha384";
    pub const ECDSA_SHA256: &'static str = "ecdsa-sha256";
    pub const RSA_SHA256: &'static str = "rsa-sha256";
    pub const RSA_SHA384: &'static str = "rsa-sha384";
    pub const RSA_SHA512: &'static str = "rsa-sha512";
}

/// The usage policy for the certificate.
#[derive(Debug, PartialEq, Ord, PartialOrd, Eq)]
pub enum UsagePolicy {
    RootCA,
    Server,
    Client,
}

pub struct RootCAParams<'a> {
    pub ca_key: &'a std::path::Path,
    pub ca_cert: &'a std::path::Path,
}

pub(crate) struct CACredentials {
    pub ca_key: rcgen::KeyPair,
    pub ca_cert: rcgen::Certificate,
}

impl<'a> TryFrom<RootCAParams<'a>> for CACredentials {
    type Error = Box<dyn Error>;
    fn try_from(params: RootCAParams<'a>) -> Result<Self, Self::Error> {
        to_ca_credentials(&params)
    }
}

/// Parameters for the generate command.
#[derive(Debug)]
pub struct GenerateParams<'a> {
    pub working_directory: &'a std::path::Path,
    pub output_directory: &'a std::path::Path,
    pub expires_in: Option<Duration>,
    pub target_name: &'a str,
    pub key_algorithm: &'a str,
    pub key_size: usize,
    pub organization: &'a str,
    pub state: &'a str,
    pub country: &'a str,
    pub subject_alt_names: &'a [String],
}

/// Generate a certificate for the given usage policy.
pub fn handle<'a>(
    params: GenerateParams<'a>,
    usage_policy: UsagePolicy,
    ca_params: Option<RootCAParams>,
) -> Result<(), Box<dyn Error>> {
    let _wdh_rai = WorkdirHandler::cwd(params.working_directory)?;
    utils::create_output_directory(params.output_directory)?;
    match usage_policy {
        UsagePolicy::RootCA => handle_root_ca(params),
        UsagePolicy::Server | UsagePolicy::Client => handle_child(
            usage_policy,
            params,
            ca_params.ok_or("missing CA params")?.try_into()?,
        ),
    }
}

fn handle_root_ca<'a>(global_params: GenerateParams<'a>) -> Result<(), Box<dyn Error>> {
    // 1. Create the root CA's private key.
    let signature_alg = utils::to_key_algorithm(global_params.key_algorithm)?;
    let ca_key = rcgen::KeyPair::generate_for(signature_alg)?;
    save_to_file(
        global_params.output_directory,
        &format!("{}.key", &global_params.target_name),
        ca_key.serialize_pem().as_bytes(),
    )?;
    // 2. Create the root CA's certificate.
    let mut cert_params = rcgen::CertificateParams::new(global_params.subject_alt_names)?;
    cert_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    set_key_usages(
        &mut cert_params,
        [
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::CrlSign,
        ]
        .into_iter(),
    );
    set_distinguished_name(
        &mut cert_params,
        &utils::DistinguishedName {
            common_name: global_params
                .subject_alt_names
                .first()
                .or(Some(&DEFAULT_COMMON_NAME.to_string()))
                .unwrap(),
            organization: global_params.organization,
            organizational_unit: &format!("{} CA", global_params.organization),
            country: global_params.country,
            state: global_params.state,
        },
    );
    set_expiration(&mut cert_params, global_params.expires_in);

    // 3. Self-sign the root CA's certificate...
    let cert = cert_params.self_signed(&ca_key)?;
    save_to_file(
        global_params.output_directory,
        &format!("{}.crt", global_params.target_name),
        cert.pem().as_bytes(),
    )?;
    Ok(())
}

fn handle_child<'a>(
    usage_policy: UsagePolicy,
    global_params: GenerateParams<'a>,
    ca_creds: CACredentials,
) -> Result<(), Box<dyn Error>> {
    // 1. Create a private key.
    let signature_alg = utils::to_key_algorithm(global_params.key_algorithm)?;
    let priv_key = rcgen::KeyPair::generate_for(signature_alg)?;
    save_to_file(
        global_params.output_directory,
        &format!("{}.key", &global_params.target_name),
        priv_key.serialize_pem().as_bytes(),
    )?;
    // 2. Create a certificate...
    let mut params = rcgen::CertificateParams::new(global_params.subject_alt_names)?;
    let unit_name = match usage_policy {
        UsagePolicy::Server => "Server",
        UsagePolicy::Client => "Client",
        _ => unreachable!(),
    };

    set_key_usages(&mut params, [KeyUsagePurpose::KeyEncipherment].into_iter());
    set_distinguished_name(
        &mut params,
        &utils::DistinguishedName {
            common_name: global_params
                .subject_alt_names
                .first()
                .or(Some(&DEFAULT_COMMON_NAME.to_string()))
                .unwrap(),
            organization: global_params.organization,
            organizational_unit: &format!("{} {}", global_params.organization, unit_name),
            country: global_params.country,
            state: global_params.state,
        },
    );
    set_expiration(&mut params, global_params.expires_in);
    match usage_policy {
        UsagePolicy::Server => {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        UsagePolicy::Client => {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        _ => unreachable!(),
    }

    let csr = params.serialize_request(&priv_key)?;
    save_to_file(
        global_params.output_directory,
        &format!("{}.csr", &global_params.target_name),
        csr.pem()?.as_bytes(),
    )?;

    let cert = params.signed_by(&priv_key, &ca_creds.ca_cert, &ca_creds.ca_key)?;
    save_to_file(
        global_params.output_directory,
        &format!("{}.crt", &global_params.target_name),
        cert.pem().as_bytes(),
    )?;
    Ok(())
}

mod utils {
    use crate::handlers::generate::{CACredentials, RootCAParams, algo};
    use rcgen::{CertificateParams, DnType, KeyUsagePurpose, SignatureAlgorithm};
    use std::error::Error;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use time::OffsetDateTime;

    pub(crate) struct WorkdirHandler {
        pub old_wd: PathBuf,
    }

    impl WorkdirHandler {
        pub(crate) fn cwd(new_wd: &Path) -> Result<WorkdirHandler, Box<dyn Error>> {
            let old_wd = std::env::current_dir()?;
            std::env::set_current_dir(&new_wd)?;
            Ok(WorkdirHandler { old_wd })
        }
    }
    impl Drop for WorkdirHandler {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.old_wd).ok();
        }
    }

    pub(crate) fn create_output_directory(path: &Path) -> Result<(), Box<dyn Error>> {
        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }
        Ok(())
    }

    pub(crate) fn save_to_file<A: AsRef<Path>>(
        dir: A,
        filename: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(PathBuf::from(dir.as_ref()).join(filename))?
            .write_all(data)
    }

    pub(crate) fn to_key_algorithm(
        name: &str,
    ) -> Result<&'static SignatureAlgorithm, Box<dyn Error>> {
        match name {
            algo::ED25519 => Ok(&rcgen::PKCS_ED25519),
            algo::ECDSA_SHA256 => Ok(&rcgen::PKCS_ECDSA_P256_SHA256),
            algo::ECDSA_SHA384 => Ok(&rcgen::PKCS_ECDSA_P384_SHA384),
            algo::RSA_SHA256 => Ok(&rcgen::PKCS_RSA_SHA256),
            algo::RSA_SHA384 => Ok(&rcgen::PKCS_RSA_SHA384),
            algo::RSA_SHA512 => Ok(&rcgen::PKCS_RSA_SHA512),
            _ => Err("unsupported signature algorithm".into()),
        }
    }

    pub(crate) fn to_ca_credentials<'a>(
        ca_params: &'a RootCAParams,
    ) -> Result<CACredentials, Box<dyn Error>> {
        let mut buffer = String::new();
        let _ = File::open(ca_params.ca_key)?.read_to_string(&mut buffer)?;
        let key = rcgen::KeyPair::from_pem(&buffer)?;
        buffer.clear();

        let _ = File::open(ca_params.ca_cert)?.read_to_string(&mut buffer)?;
        let params = CertificateParams::from_ca_cert_pem(&buffer)?;
        let cert = params.self_signed(&key)?;

        Ok(CACredentials {
            ca_key: key,
            ca_cert: cert,
        })
    }

    pub(crate) struct DistinguishedName<'a> {
        pub common_name: &'a str,
        pub organization: &'a str,
        pub organizational_unit: &'a str,
        pub country: &'a str,
        pub state: &'a str,
    }
    pub(crate) fn set_distinguished_name(
        cert_params: &mut CertificateParams,
        dn: &DistinguishedName,
    ) {
        cert_params
            .distinguished_name
            .push(DnType::CommonName, dn.common_name);
        cert_params
            .distinguished_name
            .push(DnType::OrganizationName, dn.organization);
        cert_params
            .distinguished_name
            .push(DnType::CountryName, dn.country);
        cert_params
            .distinguished_name
            .push(DnType::StateOrProvinceName, dn.state);
        cert_params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, dn.organizational_unit);
    }

    pub(crate) fn set_key_usages(
        cert_params: &mut CertificateParams,
        purposes: impl Iterator<Item = KeyUsagePurpose>,
    ) {
        for purpose in purposes {
            cert_params.key_usages.push(purpose);
        }
    }

    pub(crate) fn set_expiration(cert_params: &mut CertificateParams, expire_in: Option<Duration>) {
        cert_params.not_before = OffsetDateTime::now_utc() - Duration::from_secs(1);
        if let Some(expire_in) = expire_in {
            cert_params.not_after = OffsetDateTime::now_utc() + expire_in;
        }
    }
}
