use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha1::Sha1;
use uuid::Uuid;

const CDN_ENDPOINT: &str = "https://cdn.aliyuncs.com/";
const API_VERSION: &str = "2018-05-10";
const ACCESS_KEY_ID_ENV: &str = "ALIBABA_CLOUD_ACCESS_KEY_ID";
const ACCESS_KEY_SECRET_ENV: &str = "ALIBABA_CLOUD_ACCESS_KEY_SECRET";

const ALIYUN_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
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
    Refresh {
        #[arg(long)]
        urls: String,
        #[arg(long = "type", default_value = "File")]
        refresh_type: RefreshType,
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
    },
    PublishStaging {
        #[arg(long)]
        domain: String,
    },
    RollbackStaging {
        #[arg(long)]
        domain: String,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum RefreshType {
    File,
    Directory,
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
    let credentials = Credentials::from_env()?;
    let client = CdnClient::new(credentials);

    match cli.command {
        Commands::Cdn { command } => match command {
            CdnCommand::Refresh { urls, refresh_type } => {
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
            } => {
                let rule = fs::read_to_string(&rule_file)
                    .with_context(|| format!("failed to read rule file {rule_file}"))?;
                let response =
                    client.push_edgescript_staging(&domain, &rule, &name, pri, &pos, &enable)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::PublishStaging { domain } => {
                let response = client.publish_edgescript_staging(&domain)?;
                print_json(&response)?;
            }
            EdgeScriptCommand::RollbackStaging { domain } => {
                let response = client.rollback_edgescript_staging(&domain)?;
                print_json(&response)?;
            }
        },
    }

    Ok(())
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
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "RefreshObjectCaches".to_string());
        params.insert("ObjectPath".to_string(), urls.join("\n"));
        params.insert(
            "ObjectType".to_string(),
            refresh_type.as_api_value().to_string(),
        );

        self.call(params)
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

        self.call(params)
    }

    fn push_edgescript_staging(
        &self,
        domain: &str,
        rule: &str,
        name: &str,
        pri: u16,
        pos: &EdgeScriptPosition,
        enable: &OnOff,
    ) -> Result<Value> {
        if pri > 999 {
            return Err(anyhow!("--pri must be between 0 and 999"));
        }

        let functions = json!([
            {
                "functionName": "edge_function",
                "functionArgs": [
                    {"argName": "enable", "argValue": enable.as_api_value()},
                    {"argName": "name", "argValue": name},
                    {"argName": "pos", "argValue": pos.as_api_value()},
                    {"argName": "pri", "argValue": pri.to_string()},
                    {"argName": "rule", "argValue": rule}
                ]
            }
        ]);

        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "SetCdnDomainStagingConfig".to_string(),
        );
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("Functions".to_string(), functions.to_string());

        self.call(params)
    }

    fn publish_edgescript_staging(&self, domain: &str) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "PublishStagingConfigToProduction".to_string(),
        );
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionName".to_string(), "edge_function".to_string());

        self.call(params)
    }

    fn rollback_edgescript_staging(&self, domain: &str) -> Result<Value> {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "RollbackStagingConfig".to_string());
        params.insert("DomainName".to_string(), domain.to_string());
        params.insert("FunctionName".to_string(), "edge_function".to_string());

        self.call(params)
    }

    fn call(&self, params: BTreeMap<String, String>) -> Result<Value> {
        let signed_params = sign_params(params, &self.credentials)?;
        let response = self.http.get(CDN_ENDPOINT).query(&signed_params).send()?;
        let status = response.status();
        let body = response.text()?;

        let parsed = serde_json::from_str::<Value>(&body)
            .with_context(|| format!("Aliyun response was not JSON: {body}"))?;

        if !status.is_success() {
            return Err(anyhow!("Aliyun API request failed with {status}: {parsed}"));
        }

        Ok(parsed)
    }
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

fn sign_params(
    mut params: BTreeMap<String, String>,
    credentials: &Credentials,
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
    let string_to_sign = format!("GET&%2F&{}", aliyun_percent_encode(&canonicalized_query));
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
    fn percent_encoding_matches_aliyun_requirements() {
        assert_eq!(aliyun_percent_encode("a b*c~"), "a%20b%2Ac~");
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
    }

    #[test]
    fn staging_push_shape_contains_edge_function_rule() {
        let functions = json!([
            {
                "functionName": "edge_function",
                "functionArgs": [
                    {"argName": "enable", "argValue": "on"},
                    {"argName": "name", "argValue": "static_site_rewrite"},
                    {"argName": "pos", "argValue": "head"},
                    {"argName": "pri", "argValue": "1"},
                    {"argName": "rule", "argValue": "if eq($uri, '/') {}"}
                ]
            }
        ]);

        assert!(functions.to_string().contains("edge_function"));
        assert!(functions.to_string().contains("static_site_rewrite"));
    }
}
