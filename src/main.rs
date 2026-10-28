use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::{Method, Url};
use serde_json::{json, Value};
use sha1::Sha1;
use uuid::Uuid;

const CDN_ENDPOINT: &str = "https://cdn.aliyuncs.com/";
const API_VERSION: &str = "2018-05-10";
const ACCESS_KEY_ID_ENV: &str = "ALIBABA_CLOUD_ACCESS_KEY_ID";
const ACCESS_KEY_SECRET_ENV: &str = "ALIBABA_CLOUD_ACCESS_KEY_SECRET";

const ALIYUN_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Parser, Debug)]
#[command(name = "aliyun-tools")]
#[command(about = "Small Aliyun CDN operations helper")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Cdn {
        #[command(subcommand)]
        command: CdnCommand,
    },
    Edgescript {
        #[command(subcommand)]
        command: EdgeScriptCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CdnCommand {
    /// Query or update a CDN domain's HTTPS certificate.
    Cert {
        #[command(subcommand)]
        command: CertificateCommand,
    },
    Refresh {
        #[arg(long)]
        urls: String,
        #[arg(long = "type", default_value = "File")]
        refresh_type: RefreshType,
    },
}

#[derive(Subcommand, Debug)]
enum CertificateCommand {
    Query {
        #[arg(long)]
        domain: String,
    },
    /// Upload a PEM certificate chain and private key, enabling HTTPS.
    Update {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        cert_file: String,
        #[arg(long)]
        key_file: String,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum EdgeScriptCommand {
    Query {
        #[arg(long)]
        domain: String,
        #[arg(long = "env", value_enum, default_value = "production")]
        environment: EdgeScriptEnv,
    },
    PushStaging {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        rule_file: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 1)]
        pri: u16,
        #[arg(long, value_enum, default_value = "head")]
        pos: EdgeScriptPosition,
        #[arg(long, value_enum, default_value = "on")]
        enable: OnOff,
        #[arg(long, value_enum, default_value = "upsert")]
        mode: EdgeScriptPushMode,
    },
    PublishStaging {
        #[arg(long)]
        domain: String,
    },
    SyncProductionToStaging {
        #[arg(long)]
        domain: String,
    },
    RollbackStaging {
        #[arg(long)]
        domain: String,
    },
    TestStaging {
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "staging.myalicdn.com")]
        staging_domain: String,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RefreshType {
    File,
    Directory,
}

impl FromStr for RefreshType {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "file" => Ok(Self::File),
            "directory" => Ok(Self::Directory),
            _ => Err(format!(
                "invalid refresh type {value}; expected File or Directory"
            )),
        }
    }
}

impl RefreshType {
    fn as_api_value(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum EdgeScriptEnv {
    Production,
    Staging,
}

#[derive(Clone, Debug, ValueEnum)]
enum EdgeScriptPosition {
    Head,
    Foot,
}

impl EdgeScriptPosition {
    fn as_api_value(&self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Foot => "foot",
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum EdgeScriptPushMode {
    Upsert,
    Append,
}

#[derive(Clone, Debug, ValueEnum)]
enum OnOff {
    On,
    Off,
}

impl OnOff {
    fn as_api_value(&self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Debug)]
struct Credentials {
    access_key_id: String,
    access_key_secret: String,
}

impl Credentials {
    fn from_env() -> Result<Self> {
        let access_key_id = env::var(ACCESS_KEY_ID_ENV)
            .with_context(|| format!("{ACCESS_KEY_ID_ENV} environment variable is required"))?;
        let access_key_secret = env::var(ACCESS_KEY_SECRET_ENV)
            .with_context(|| format!("{ACCESS_KEY_SECRET_ENV} environment variable is required"))?;

        Ok(Self {
            access_key_id,
            access_key_secret,
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Cdn { command } => match command {
            CdnCommand::Cert { command } => {
                let response = match command {
                    CertificateCommand::Query { domain } => cdn_client_from_env()?.call(
                        Method::GET,
                        BTreeMap::from([
                            (
                                "Action".to_string(),
                                "DescribeDomainCertificateInfo".to_string(),
                            ),
                            ("DomainName".to_string(), domain),
                        ]),
                    )?,
                    CertificateCommand::Update {
                        domain,
                        cert_file,
                        key_file,
                        name,
                    } => {
                        let certificate = fs::read_to_string(&cert_file).with_context(|| {
                            format!("failed to read certificate file {cert_file}")
                        })?;
                        let private_key = fs::read_to_string(&key_file).with_context(|| {
                            format!("failed to read private key file {key_file}")
                        })?;
                        cdn_client_from_env()?.call(
                            Method::POST,
                            certificate_update_params(&domain, certificate, private_key, name),
                        )?
                    }
                };
                print_json(&response)?;
            }
            CdnCommand::Refresh { urls, refresh_type } => {
                let client = cdn_client_from_env()?;
                let urls = parse_refresh_urls(&urls, &refresh_type)?;
                let response = client.refresh_object_caches(&urls, &refresh_type)?;
                print_json(&response)?;
            }
        },
        Commands::Edgescript { command } => match command {
            EdgeScriptCommand::Query {
                domain,
                environment,
            } => {
                let client = cdn_client_from_env()?;
                let response = client.query_edgescript(&domain, &environment)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::PushStaging {
                domain,
                rule_file,
                name,
                pri,
                pos,
                enable,
                mode,
            } => {
                let client = cdn_client_from_env()?;
                let rule = fs::read_to_string(&rule_file)
                    .with_context(|| format!("failed to read rule file {rule_file}"))?;
                if pri > 999 {
                    return Err(anyhow!("--pri must be between 0 and 999"));
                }
                let config_id = match mode {
                    EdgeScriptPushMode::Upsert => {
                        client.find_edgescript_config_id(&domain, &name)?
                    }
                    EdgeScriptPushMode::Append => None,
                };
                let functions =
                    edgescript_staging_functions(&rule, &name, pri, &pos, &enable, config_id)?;
                let response = client.set_edgescript_staging_config(&domain, functions)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::PublishStaging { domain } => {
                let client = cdn_client_from_env()?;
                let response = client.publish_edgescript_staging(&domain)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::SyncProductionToStaging { domain } => {
                let client = cdn_client_from_env()?;
                let response = client.sync_edgescript_production_to_staging(&domain)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::RollbackStaging { domain } => {
                let client = cdn_client_from_env()?;
                let response = client.rollback_edgescript_staging(&domain)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::TestStaging {
                url,
                staging_domain,
                timeout_seconds,
            } => {
                test_edgescript_staging_url(
                    &url,
                    &staging_domain,
                    Duration::from_secs(timeout_seconds),
                )?;
            }
        },
    }

    Ok(())
}

fn cdn_client_from_env() -> Result<CdnClient> {
    Ok(CdnClient::new(Credentials::from_env()?))
}

#[derive(Debug)]
struct CdnClient {
    credentials: Credentials,
    http: Client,
}

impl CdnClient {
    fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            http: Client::new(),
        }
    }

    fn refresh_object_caches(&self, urls: &[String], refresh_type: &RefreshType) -> Result<Value> {
        self.call(
            Method::GET,
            refresh_object_caches_params(urls, refresh_type),
        )
    }

    fn query_edgescript(&self, domain: &str, environment: &EdgeScriptEnv) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            match environment {
                EdgeScriptEnv::Production => "DescribeCdnDomainConfigs",
                EdgeScriptEnv::Staging => "DescribeCdnDomainStagingConfig",
            }
            .to_string(),
        );
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionNames".to_string(), "edge_function".to_string());

        self.call(Method::GET, params)
    }

    fn set_edgescript_staging_config(&self, domain: &str, functions: Value) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "SetCdnDomainStagingConfig".to_string(),
        );
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("Functions".to_string(), functions.to_string());

        self.call(Method::GET, params)
    }

    fn find_edgescript_config_id(&self, domain: &str, name: &str) -> Result<Option<String>> {
        let staging = self.query_edgescript(domain, &EdgeScriptEnv::Staging)?;
        if let Some(config_id) = find_edgescript_config_id(&staging, name)? {
            return Ok(Some(config_id));
        }

        let production = self.query_edgescript(domain, &EdgeScriptEnv::Production)?;
        find_edgescript_config_id(&production, name)
    }

    fn publish_edgescript_staging(&self, domain: &str) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "PublishStagingConfigToProduction".to_string(),
        );
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionName".to_string(), "edge_function".to_string());

        self.call(Method::GET, params)
    }

    fn rollback_edgescript_staging(&self, domain: &str) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "RollbackStagingConfig".to_string());
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionName".to_string(), "edge_function".to_string());

        let (status, response) = self.request(Method::GET, params)?;
        if status == reqwest::StatusCode::NOT_FOUND
            && response.get("Code").and_then(Value::as_str) == Some("StagingConfig.NotFound")
        {
            eprintln!("No staging config exists.");
            return Ok(response);
        }

        if !status.is_success() {
            return Err(anyhow!(
                "Aliyun API request failed with {status}: {response}"
            ));
        }

        Ok(response)
    }

    fn sync_edgescript_production_to_staging(&self, domain: &str) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "CopyOnlineConfig".to_string());
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionName".to_string(), "edge_function".to_string());

        self.call(Method::GET, params)
    }

    fn build_request(
        &self,
        method: Method,
        params: BTreeMap<String, String>,
    ) -> Result<reqwest::blocking::Request> {
        let signed_params = sign_params(params, &self.credentials, &method)?;
        let request = self.http.request(method.clone(), CDN_ENDPOINT);
        let request = if method == Method::GET {
            request.query(&signed_params)
        } else {
            request.form(&signed_params)
        };
        Ok(request.build()?)
    }

    fn request(
        &self,
        method: Method,
        params: BTreeMap<String, String>,
    ) -> Result<(reqwest::StatusCode, Value)> {
        let request = self.build_request(method, params)?;
        let response = self.http.execute(request)?;
        let status = response.status();
        let body = response.text()?;

        let parsed = serde_json::from_str::<Value>(&body)
            .with_context(|| format!("Aliyun response was not JSON: {body}"))?;

        Ok((status, parsed))
    }

    fn call(&self, method: Method, params: BTreeMap<String, String>) -> Result<Value> {
        let (status, parsed) = self.request(method, params)?;
        if !status.is_success() {
            return Err(anyhow!("Aliyun API request failed with {status}: {parsed}"));
        }

        Ok(parsed)
    }
}

fn certificate_update_params(
    domain: &str,
    certificate: String,
    private_key: String,
    name: Option<String>,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::from([
        (
            "Action".to_string(),
            "SetCdnDomainSSLCertificate".to_string(),
        ),
        ("DomainName".to_string(), domain.to_string()),
        ("CertType".to_string(), "upload".to_string()),
        ("SSLProtocol".to_string(), "on".to_string()),
        ("SSLPub".to_string(), certificate),
        ("SSLPri".to_string(), private_key),
    ]);
    if let Some(name) = name {
        params.insert("CertName".to_string(), name);
    }
    params
}

fn refresh_object_caches_params(
    urls: &[String],
    refresh_type: &RefreshType,
) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("Action".to_string(), "RefreshObjectCaches".to_string());
    params.insert("ObjectPath".to_string(), urls.join("\n"));
    params.insert(
        "ObjectType".to_string(),
        refresh_type.as_api_value().to_string(),
    );
    params
}

fn parse_refresh_urls(urls: &str, refresh_type: &RefreshType) -> Result<Vec<String>> {
    let mut parsed = urls
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if parsed.is_empty() {
        return Err(anyhow!("--urls must include at least one URL"));
    }

    if matches!(refresh_type, RefreshType::Directory) {
        for url in &mut parsed {
            if !url.ends_with('/') {
                url.push('/');
            }
        }
    }

    Ok(parsed)
}

fn edgescript_staging_functions(
    rule: &str,
    name: &str,
    pri: u16,
    pos: &EdgeScriptPosition,
    enable: &OnOff,
    config_id: Option<String>,
) -> Result<Value> {
    let mut function = json!({
        "functionId": 180,
        "functionName": "edge_function",
        "functionArgs": [
            {"argName": "enable", "argValue": enable.as_api_value()},
            {"argName": "name", "argValue": name},
            {"argName": "pos", "argValue": pos.as_api_value()},
            {"argName": "pri", "argValue": pri.to_string()},
            {"argName": "rule", "argValue": rule}
        ]
    });

    if let Some(config_id) = config_id {
        function["configId"] = Value::Number(
            config_id
                .parse::<u64>()
                .with_context(|| format!("ConfigId {config_id} is not numeric"))?
                .into(),
        );
    }

    Ok(Value::Array(vec![function]))
}

fn find_edgescript_config_id(response: &Value, name: &str) -> Result<Option<String>> {
    let Some(functions) = response
        .pointer("/DomainConfigs/DomainConfig")
        .or_else(|| response.pointer("/DomainConfigList/DomainConfig"))
        .or_else(|| response.pointer("/DomainConfigs"))
        .or_else(|| response.pointer("/DomainConfigList"))
    else {
        return Ok(None);
    };

    for function in value_items(functions) {
        let function_name = function
            .get("FunctionName")
            .or_else(|| function.get("functionName"))
            .and_then(Value::as_str);
        if function_name != Some("edge_function") {
            continue;
        }

        if edgescript_arg_value(function, "name") == Some(name) {
            let config_id = function
                .get("ConfigId")
                .or_else(|| function.get("configId"))
                .and_then(value_to_string)
                .ok_or_else(|| {
                    anyhow!("edge_function {name} matched but did not include ConfigId")
                })?;
            return Ok(Some(config_id));
        }
    }

    Ok(None)
}

fn value_items(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

fn edgescript_arg_value<'a>(function: &'a Value, arg_name: &str) -> Option<&'a str> {
    let args = function
        .get("FunctionArgs")
        .or_else(|| function.get("functionArgs"))?;
    let args = args
        .get("FunctionArg")
        .or_else(|| args.get("functionArg"))
        .unwrap_or(args);

    for arg in value_items(args) {
        if arg.get("ArgName").and_then(Value::as_str) == Some(arg_name)
            || arg.get("argName").and_then(Value::as_str) == Some(arg_name)
        {
            return arg
                .get("ArgValue")
                .or_else(|| arg.get("argValue"))
                .and_then(Value::as_str);
        }
    }

    None
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn resolve_staging_addrs(staging_domain: &str) -> Result<Vec<SocketAddr>> {
    let addrs = (staging_domain, 443)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {staging_domain}"))?
        .collect::<Vec<_>>();

    if addrs.is_empty() {
        return Err(anyhow!("{staging_domain} did not resolve to any addresses"));
    }

    Ok(addrs)
}

fn test_edgescript_staging_url(url: &str, staging_domain: &str, timeout: Duration) -> Result<()> {
    let url = Url::parse(url).with_context(|| format!("invalid staging test URL: {url}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("staging test URL must include a host"))?;
    if url.scheme() != "https" {
        return Err(anyhow!("staging test URL must use https"));
    }

    let addrs = resolve_staging_addrs(staging_domain)?;

    println!(
        "Resolved {staging_domain} to {}",
        addrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let addr = test_edgescript_staging_host(url.as_str(), host, &addrs, timeout)?;
    println!("OK {} via {addr}", url.as_str());
    Ok(())
}

fn test_edgescript_staging_host(
    url: &str,
    host: &str,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<SocketAddr> {
    let mut errors = Vec::new();

    for addr in addrs {
        let response = staging_test_client(host, *addr, timeout)
            .get(url)
            .header("user-agent", "aliyun-tools/edgescript-staging-test")
            .send();

        match response {
            Ok(response)
                if response.status().is_success() || response.status().is_redirection() =>
            {
                return Ok(*addr);
            }
            Ok(response) => errors.push(format!("{addr} returned {}", response.status())),
            Err(err) => errors.push(format!("{addr} failed: {err}")),
        }
    }

    Err(anyhow!("{}", errors.join("; ")))
}

fn staging_test_client(host: &str, addr: SocketAddr, timeout: Duration) -> Client {
    ClientBuilder::new()
        .resolve(host, addr)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("staging test client configuration is valid")
}

fn sign_params(
    mut params: BTreeMap<String, String>,
    credentials: &Credentials,
    method: &Method,
) -> Result<BTreeMap<String, String>> {
    params.insert("Format".to_string(), "JSON".to_string());
    params.insert("Version".to_string(), API_VERSION.to_string());
    params.insert("AccessKeyId".to_string(), credentials.access_key_id.clone());
    params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
    params.insert("SignatureVersion".to_string(), "1.0".to_string());
    params.insert("SignatureNonce".to_string(), Uuid::new_v4().to_string());
    params.insert(
        "Timestamp".to_string(),
        aliyun_timestamp(SystemTime::now())?,
    );

    let canonicalized_query = canonicalized_query(&params);
    let string_to_sign = format!(
        "{method}&%2F&{}",
        aliyun_percent_encode(&canonicalized_query)
    );
    let signature = signature(&string_to_sign, &credentials.access_key_secret)?;
    params.insert("Signature".to_string(), signature);

    Ok(params)
}

fn canonicalized_query(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                aliyun_percent_encode(key),
                aliyun_percent_encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn signature(string_to_sign: &str, access_key_secret: &str) -> Result<String> {
    let key = format!("{access_key_secret}&");
    let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes())
        .map_err(|_| anyhow!("failed to initialize HMAC signer"))?;
    mac.update(string_to_sign.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

fn aliyun_percent_encode(value: &str) -> String {
    utf8_percent_encode(value, ALIYUN_ENCODE_SET).to_string()
}

fn aliyun_timestamp(now: SystemTime) -> Result<String> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?
        .as_secs();
    Ok(format_unix_timestamp_utc(seconds))
}

fn format_unix_timestamp_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let secs_of_day = (seconds % 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_directory_urls_with_trailing_slashes() {
        let urls = parse_refresh_urls(
            "https://example.com/a, https://example.com/b/",
            &RefreshType::Directory,
        )
        .unwrap();

        assert_eq!(
            urls,
            vec![
                "https://example.com/a/".to_string(),
                "https://example.com/b/".to_string()
            ]
        );
    }

    #[test]
    fn rejects_empty_refresh_urls() {
        assert!(parse_refresh_urls(" , ", &RefreshType::File).is_err());
    }

    #[test]
    fn parses_cdn_refresh_cli_with_ci_refresh_type_value() {
        let cli = Cli::try_parse_from([
            "aliyun-tools",
            "cdn",
            "refresh",
            "--urls",
            "https://example.com/app",
            "--type",
            "Directory",
        ])
        .unwrap();

        let Commands::Cdn { command } = cli.command else {
            panic!("expected cdn command");
        };
        let CdnCommand::Refresh { urls, refresh_type } = command else {
            panic!("expected refresh command");
        };
        assert_eq!(urls, "https://example.com/app");
        assert_eq!(refresh_type, RefreshType::Directory);
    }

    #[test]
    fn builds_cdn_refresh_request_params() {
        let urls = vec![
            "https://example.com/a/".to_string(),
            "https://example.com/b/".to_string(),
        ];
        let params = refresh_object_caches_params(&urls, &RefreshType::Directory);

        assert_eq!(params.get("Action").unwrap(), "RefreshObjectCaches");
        assert_eq!(params.get("ObjectType").unwrap(), "directory");
        assert_eq!(
            params.get("ObjectPath").unwrap(),
            "https://example.com/a/\nhttps://example.com/b/"
        );
    }

    #[test]
    fn percent_encoding_matches_aliyun_requirements() {
        assert_eq!(aliyun_percent_encode("a b*c~!"), "a%20b%2Ac~%21");
        assert_eq!(aliyun_percent_encode("/?:&="), "%2F%3F%3A%26%3D");
    }

    #[test]
    fn formats_utc_timestamp() {
        assert_eq!(format_unix_timestamp_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_unix_timestamp_utc(1_704_067_200),
            "2024-01-01T00:00:00Z"
        );
    }

    #[test]
    fn builds_canonicalized_query_in_sorted_order() {
        let mut params = BTreeMap::new();
        params.insert("Version".to_string(), "2018-05-10".to_string());
        params.insert("Action".to_string(), "RefreshObjectCaches".to_string());
        params.insert(
            "ObjectPath".to_string(),
            "https://example.com/a/".to_string(),
        );

        assert_eq!(
            canonicalized_query(&params),
            "Action=RefreshObjectCaches&ObjectPath=https%3A%2F%2Fexample.com%2Fa%2F&Version=2018-05-10"
        );
    }

    #[test]
    fn signs_known_string() {
        let value = signature("GET&%2F&Action%3DTest", "secret").unwrap();
        assert_eq!(value, "vqA/LwIo/qiGVRH8r7L/RtWdrNM=");
        assert_eq!(
            signature("POST&%2F&Action%3DTest", "secret").unwrap(),
            "IRD2nMyxYMLPfAcYXB1u8Mhupbo="
        );
    }

    #[test]
    fn parses_certificate_commands_and_requires_both_files_for_update() {
        let query = Cli::try_parse_from([
            "aliyun-tools",
            "cdn",
            "cert",
            "query",
            "--domain",
            "example.com",
        ])
        .unwrap();
        assert!(matches!(query.command, Commands::Cdn {
            command: CdnCommand::Cert { command: CertificateCommand::Query { domain } }
        } if domain == "example.com"));

        let args = [
            "aliyun-tools",
            "cdn",
            "cert",
            "update",
            "--domain",
            ".example.com",
            "--cert-file",
            "chain.pem",
            "--key-file",
            "private.key",
        ];
        let update = Cli::try_parse_from(args).unwrap();
        assert!(matches!(update.command, Commands::Cdn {
            command: CdnCommand::Cert {
                command: CertificateCommand::Update { domain, cert_file, key_file, name: None }
            }
        } if domain == ".example.com" && cert_file == "chain.pem" && key_file == "private.key"));
        assert!(Cli::try_parse_from(&args[..8]).is_err());
        assert!(Cli::try_parse_from([
            "aliyun-tools",
            "cdn",
            "cert",
            "update",
            "--domain",
            "example.com",
            "--key-file",
            "private.key",
        ])
        .is_err());
    }

    #[test]
    fn certificate_update_posts_complete_pem_and_signs_the_post_body() {
        let client = CdnClient::new(Credentials {
            access_key_id: "test-id".to_string(),
            access_key_secret: "secret".to_string(),
        });
        let certificate =
            "-----BEGIN CERTIFICATE-----\nA+B/C==\n-----END CERTIFICATE-----\n".repeat(3);
        let private_key = "-----BEGIN PRIVATE KEY-----\nD+E/F==\n-----END PRIVATE KEY-----\n";
        let request = client
            .build_request(
                Method::POST,
                certificate_update_params(
                    ".example.com",
                    certificate.clone(),
                    private_key.to_string(),
                    Some("renewal!2026".to_string()),
                ),
            )
            .unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.url().as_str(), CDN_ENDPOINT);
        assert_eq!(
            request.headers()["content-type"],
            "application/x-www-form-urlencoded"
        );
        let mut params: BTreeMap<String, String> = reqwest::Url::parse(&format!(
            "https://example.com/?{}",
            std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap()
        ))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
        assert_eq!(params["Action"], "SetCdnDomainSSLCertificate");
        assert_eq!(params["DomainName"], ".example.com");
        assert_eq!(params["SSLProtocol"], "on");
        assert_eq!(params["CertType"], "upload");
        assert_eq!(params["CertName"], "renewal!2026");
        assert_eq!(params["SSLPub"], certificate);
        assert_eq!(params["SSLPri"], private_key);
        let actual_signature = params.remove("Signature").unwrap();
        let canonical = aliyun_percent_encode(&canonicalized_query(&params));
        assert!(canonical.contains("CertName%3Drenewal%25212026"));
        assert_eq!(
            actual_signature,
            signature(&format!("POST&%2F&{canonical}"), "secret").unwrap()
        );
        assert_ne!(
            actual_signature,
            signature(&format!("GET&%2F&{canonical}"), "secret").unwrap()
        );
    }

    #[test]
    fn existing_get_requests_keep_query_parameters_and_get_signature() {
        let client = CdnClient::new(Credentials {
            access_key_id: "test-id".to_string(),
            access_key_secret: "secret".to_string(),
        });
        let request = client
            .build_request(
                Method::GET,
                refresh_object_caches_params(
                    &["https://example.com/".to_string()],
                    &RefreshType::Directory,
                ),
            )
            .unwrap();
        assert_eq!(request.method(), Method::GET);
        assert!(request.body().is_none());
        let mut params: BTreeMap<String, String> =
            request.url().query_pairs().into_owned().collect();
        assert_eq!(params["Action"], "RefreshObjectCaches");
        assert_eq!(params["ObjectPath"], "https://example.com/");
        let actual_signature = params.remove("Signature").unwrap();
        let canonical = aliyun_percent_encode(&canonicalized_query(&params));
        assert_eq!(
            actual_signature,
            signature(&format!("GET&%2F&{canonical}"), "secret").unwrap()
        );
    }

    #[test]
    fn staging_push_shape_contains_edge_function_rule() {
        let functions = edgescript_staging_functions(
            "if eq($uri, '/') {}",
            "static_site_rewrite",
            1,
            &EdgeScriptPosition::Head,
            &OnOff::On,
            None,
        )
        .unwrap();

        assert!(functions.to_string().contains("edge_function"));
        assert!(functions.to_string().contains("static_site_rewrite"));
        assert!(!functions.to_string().contains("configId"));
        assert_eq!(functions[0]["functionId"], 180);
    }

    #[test]
    fn staging_push_shape_contains_config_id_when_updating() {
        let functions = edgescript_staging_functions(
            "if eq($uri, '/') {}",
            "static_site_rewrite",
            1,
            &EdgeScriptPosition::Head,
            &OnOff::On,
            Some("123456".to_string()),
        )
        .unwrap();

        assert_eq!(functions[0]["configId"], 123456);
    }

    #[test]
    fn builds_staging_config_function_payload() {
        let functions = edgescript_staging_functions(
            "if eq($uri, '/') {}",
            "static_site_rewrite",
            1,
            &EdgeScriptPosition::Head,
            &OnOff::On,
            Some("123456".to_string()),
        )
        .unwrap();

        assert_eq!(functions[0]["functionId"], 180);
        assert_eq!(functions[0]["functionName"], "edge_function");
        assert_eq!(functions[0]["configId"], 123456);
        assert_eq!(functions[0]["functionArgs"][1]["argName"], "name");
        assert_eq!(
            functions[0]["functionArgs"][1]["argValue"],
            "static_site_rewrite"
        );
    }

    #[test]
    fn finds_edgescript_config_id_by_name() {
        let response = json!({
            "DomainConfigs": {
                "DomainConfig": [
                    {
                        "ConfigId": 111,
                        "FunctionName": "edge_function",
                        "FunctionArgs": {
                            "FunctionArg": [
                                {"ArgName": "name", "ArgValue": "other_rule"}
                            ]
                        }
                    },
                    {
                        "ConfigId": "222",
                        "FunctionName": "edge_function",
                        "FunctionArgs": {
                            "FunctionArg": [
                                {"ArgName": "name", "ArgValue": "static_site_rewrite"}
                            ]
                        }
                    }
                ]
            }
        });

        let config_id = find_edgescript_config_id(&response, "static_site_rewrite").unwrap();
        assert_eq!(config_id.as_deref(), Some("222"));
    }

    #[test]
    fn finds_edgescript_config_id_from_staging_shape() {
        let response = json!({
            "DomainConfigs": [
                {
                    "configId": "staging-config",
                    "FunctionName": "edge_function",
                    "functionArgs": [
                        {"argName": "name", "argValue": "static_site_rewrite"}
                    ]
                }
            ]
        });

        let config_id = find_edgescript_config_id(&response, "static_site_rewrite").unwrap();
        assert_eq!(config_id.as_deref(), Some("staging-config"));
    }

    #[test]
    fn finds_edgescript_config_id_from_lowercase_function_name() {
        let response = json!({
            "DomainConfigList": {
                "DomainConfig": {
                    "configId": "lowercase-config",
                    "functionName": "edge_function",
                    "functionArgs": [
                        {"argName": "name", "argValue": "static_site_rewrite"}
                    ]
                }
            }
        });

        let config_id = find_edgescript_config_id(&response, "static_site_rewrite").unwrap();
        assert_eq!(config_id.as_deref(), Some("lowercase-config"));
    }

    #[test]
    fn ignores_non_matching_edgescript_rules() {
        let response = json!({
            "DomainConfigs": {
                "DomainConfig": {
                    "ConfigId": 111,
                    "FunctionName": "edge_function",
                    "FunctionArgs": {
                        "FunctionArg": [
                            {"ArgName": "name", "ArgValue": "other_rule"}
                        ]
                    }
                }
            }
        });

        let config_id = find_edgescript_config_id(&response, "static_site_rewrite").unwrap();
        assert_eq!(config_id, None);
    }

    #[test]
    fn errors_when_matching_edgescript_rule_has_no_config_id() {
        let response = json!({
            "DomainConfigs": {
                "DomainConfig": {
                    "FunctionName": "edge_function",
                    "FunctionArgs": {
                        "FunctionArg": [
                            {"ArgName": "name", "ArgValue": "static_site_rewrite"}
                        ]
                    }
                }
            }
        });

        let err = find_edgescript_config_id(&response, "static_site_rewrite").unwrap_err();
        assert!(err.to_string().contains("did not include ConfigId"));
    }

    #[test]
    fn parses_push_staging_default_upsert_mode() {
        let cli = Cli::try_parse_from([
            "aliyun-tools",
            "edgescript",
            "push-staging",
            "--domain",
            ".aiyou178.com",
            "--rule-file",
            "cdn/edgescript.generated.es",
            "--name",
            "static_site_rewrite",
        ])
        .unwrap();

        let Commands::Edgescript { command } = cli.command else {
            panic!("expected edgescript command");
        };
        let EdgeScriptCommand::PushStaging { mode, .. } = command else {
            panic!("expected push-staging command");
        };
        assert!(matches!(mode, EdgeScriptPushMode::Upsert));
    }

    #[test]
    fn parses_push_staging_append_mode() {
        let cli = Cli::try_parse_from([
            "aliyun-tools",
            "edgescript",
            "push-staging",
            "--domain",
            ".aiyou178.com",
            "--rule-file",
            "cdn/edgescript.generated.es",
            "--name",
            "static_site_rewrite",
            "--mode",
            "append",
        ])
        .unwrap();

        let Commands::Edgescript { command } = cli.command else {
            panic!("expected edgescript command");
        };
        let EdgeScriptCommand::PushStaging { mode, .. } = command else {
            panic!("expected push-staging command");
        };
        assert!(matches!(mode, EdgeScriptPushMode::Append));
    }

    #[test]
    fn parses_single_staging_test_url_cli() {
        let cli = Cli::try_parse_from([
            "aliyun-tools",
            "edgescript",
            "test-staging",
            "--url",
            "https://admin2.aiyou178.com/",
        ])
        .unwrap();

        let Commands::Edgescript { command } = cli.command else {
            panic!("expected edgescript command");
        };
        let EdgeScriptCommand::TestStaging { url, .. } = command else {
            panic!("expected test-staging command");
        };
        assert_eq!(url, "https://admin2.aiyou178.com/");
    }

    #[test]
    fn parses_sync_production_to_staging_cli() {
        let cli = Cli::try_parse_from([
            "aliyun-tools",
            "edgescript",
            "sync-production-to-staging",
            "--domain",
            ".aiyou178.com",
        ])
        .unwrap();

        let Commands::Edgescript { command } = cli.command else {
            panic!("expected edgescript command");
        };
        let EdgeScriptCommand::SyncProductionToStaging { domain } = command else {
            panic!("expected sync-production-to-staging command");
        };
        assert_eq!(domain, ".aiyou178.com");
    }

    #[test]
    fn rejects_non_https_staging_test_url() {
        let err = test_edgescript_staging_url(
            "http://admin2.aiyou178.com/",
            "staging.invalid",
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(err.to_string().contains("must use https"));
    }
}
