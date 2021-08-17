pub mod config;
pub mod dns_utils;
use anyhow::{anyhow, Context, Result};
use clap::{App, Arg};
use config::Config;
use dns_utils::{create_dns_query, parse_dns_answer};
use odoh_rs::protocol::{
    create_query_msg, get_supported_config, parse_received_response, ObliviousDoHConfigContents,
    ObliviousDoHQueryBody, ODOH_HTTP_HEADER,
};
use reqwest::{
    header::{HeaderMap, ACCEPT, CACHE_CONTROL, CONTENT_TYPE, PROXY_AUTHORIZATION, PRAGMA},
    Client, Response, StatusCode, ClientBuilder,
};
use std::env;
use url::Url;
use std::fs::File;
use std::io::Read;
use serde::{Deserialize, Serialize};
extern crate base64;
use std::str::FromStr;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

const QUERY_PATH: &str = "/dns-query";
const API_PATH: &str = "/api/v1/odoh-config";

#[derive(Clone, Debug)]
struct ClientSession {
    pub client: Client,
    pub target: Url,
    pub odoh_config: ODOHConfig,
    pub proxy: Option<Url>,
    pub client_secret: Option<Vec<u8>>,
    pub target_config: ObliviousDoHConfigContents,
    pub query: Option<ObliviousDoHQueryBody>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ODOHConfig {
    default: Vec<Default>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Default {
    alpn: Vec<String>,
    target_host: String,
    target_path: String,
    auth_to_target: Option<AuthToTarget>,
    odoh_configs: Vec<OdohConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct AuthToTarget {
    header_name: String,
    auth_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct OdohConfig {
    config: String,
}

#[derive(Clone, Debug)]
struct ApiSession {
    pub client: Client,
    pub target: Url
}

impl ApiSession {
    // Create a new ApiSession

    pub async fn new(config: Config) -> Result<Self> {
        let mut target = Url::parse(&config.server.target)?;
        target.set_path(API_PATH);
        let client;
        // If target is not public server and needs client certificate, 
        // Below will read cert and create client based on Identity
        if let Some(c) = &config.server.cert {
            let mut buf = Vec::new();
            File::open(c)?
                .read_to_end(&mut buf)?;
            let id = reqwest::Identity::from_pem(&buf)?;
            client = reqwest::Client::builder().identity(id).danger_accept_invalid_certs(true).use_rustls_tls().build()?;
        }else {
            client = reqwest::Client::builder().danger_accept_invalid_certs(true).use_rustls_tls().build()?;
        };
        Ok(Self {
            client,
            target
        })
    }

    pub async fn send_request(&mut self, verbose:bool) -> Result<Response> {
        let mut headers = HeaderMap::new();
        if verbose {
            headers.insert(PRAGMA, "akamai-x-cache-on, akamai-x-get-extracted-values, akamai-x-get-client-ip".parse()?);
        }
        let res = self.client.get(self.target.clone()).headers(headers).send().await?;
        Ok(res)
    }

    pub async fn parse_response(&self, resp: Response, verbose:bool) -> Result<ODOHConfig> {
        if resp.status() != StatusCode::OK {
            if verbose {
                println!("-->> ODOHConfig Headers:\n{:#?}", resp.headers());
            };
            return Err(anyhow!(
                "query failed with response status code {}",
                resp.status().as_u16()
            ));
        }
        let body = resp.text().await?;
        let odoh_config : ODOHConfig = serde_json::from_str(&body)?;
        if verbose {
            println!("-->> ODOHConfig <<--\n{}\n", serde_json::to_string_pretty(&odoh_config).unwrap());
        };
        Ok(odoh_config)
    }
}

impl ClientSession {
    /// Create a new ClientSession
    pub async fn new(config: Config, odohkey: &str, verbose: bool) -> Result<Self> {
        let mut target = Url::parse(&config.server.target)?;
        let target_config: ObliviousDoHConfigContents;
        let mut odoh_config = ODOHConfig::default();
        if odohkey.is_empty() {
            // Make API call to get ODoHConfig
            let mut api_session = ApiSession::new(config.clone()).await?;
            let api_response = api_session.send_request(verbose).await?;
            odoh_config = api_session.parse_response(api_response, verbose).await?;
            
            // Use Target URL and Query Path from ODoHConfig
            let target_host = format!("https://{}", &odoh_config.default[0].target_host);
            target = Url::parse(&target_host)?;
            target.set_path(&odoh_config.default[0].target_path);
            
            let odoh = base64::decode(&odoh_config.default[0].odoh_configs[0].config).unwrap();
            let mut bytes = [0,44].to_vec();
            bytes.extend(odoh.iter().clone());
            target_config = get_supported_config(&bytes)?;
        }else{
            target.set_path(QUERY_PATH);
            let mut odohfhandle = File::open(odohkey).expect("unable to open ODOH pubkey");
            let mut filevec = Vec::new();
            // Below is the required bytes to generate odoh-config 
            // Bytes 1-2 = Length of Odoh Config
            // Bytes 3-4 = Odoh Version
            // Bytes 5-6 = Length of remaining bytes
            // Bytes 7-8 = KEM ID Bytes
            // Bytes 9-10 = KDF ID Bytes
            // Bytes 11-12 = AEAD ID Bytes
            // Bytes 13-14 = 3rd Length Bytes
            let mut bytes = [0,44,255,6,0,40,0,32,0,1,0,1,0,32].to_vec();
            let _count = odohfhandle.read_to_end(&mut filevec);
            bytes.extend(filevec.as_slice());
            target_config = get_supported_config(&bytes)?;
        };

        let proxy = if let Some(p) = &config.server.proxy {
            Url::parse(p).ok()
        } else {
            None
        };

        Ok(Self {
            client: ClientBuilder::new().danger_accept_invalid_certs(true).http2_prior_knowledge().use_rustls_tls().build()?,
            target,
            odoh_config,
            proxy,
            client_secret: None,
            target_config,
            query: None,
        })
    }

    /// Create an oblivious query from a domain and query type
    pub fn create_request(&mut self, domain: &str, qtype: &str) -> Result<Vec<u8>> {
        // create a DNS message
        let dns_msg = create_dns_query(domain, qtype)?;
        let query = ObliviousDoHQueryBody::new(&dns_msg, Some(1));
        self.query = Some(query.clone());
        let (oblivious_query, client_secret) = create_query_msg(&self.target_config, &query)?;
        self.client_secret = Some(client_secret);
        Ok(oblivious_query)
    }

    /// Set headers and build an HTTP request to send the oblivious query to the proxy/target.
    /// If a proxy is specified, the request will be sent to the proxy. However, if a proxy is absent,
    /// it will be sent directly to the target. Note that not specifying a proxy effectively nullifies
    /// the entire purpose of using ODoH.
    pub async fn send_request(&mut self, request: &[u8], auth: &str) -> Result<Response> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, ODOH_HTTP_HEADER.parse()?);
        headers.insert(ACCEPT, ODOH_HTTP_HEADER.parse()?);
        headers.insert(CACHE_CONTROL, "no-cache, no-store".parse()?);
        if auth.is_empty(){
            if let Some (auth_target) = self.odoh_config.default[0].auth_to_target.as_ref(){
                headers.insert(PROXY_AUTHORIZATION, auth_target.auth_token.parse()?);
            }   
        }else {
            headers.insert(PROXY_AUTHORIZATION, auth.parse()?);
        }
        let query = [
            (
                "targethost",
                self.target
                    .host_str()
                    .context("Target host is not a valid host string")?,
            ),
            ("targetpath", QUERY_PATH),
        ];
        let builder = if let Some(p) = &self.proxy {
            self.client.post(p.clone()).headers(headers).query(&query)
        } else {
            self.client.post(self.target.clone()).headers(headers)
        };
        let resp = builder.body(request.to_vec()).send().await?;
        Ok(resp)
    }

    /// Parse the received response from the resolver and print the answer.
    pub async fn parse_response(&self, resp: Response, verbose: bool) -> Result<()> {
        if resp.status() != StatusCode::OK {
            if verbose {
                println!("-->> ODOHConfig Headers:\n{:#?}", resp.headers());
            };
            return Err(anyhow!(
                "query failed with response status code {}",
                resp.status().as_u16()
            ));
        }
        let data = resp.bytes().await?;
        let response_body = parse_received_response(
            &self.client_secret.clone().unwrap(),
            &data,
            &self.query.clone().unwrap(),
        )?;
        parse_dns_answer(&response_body.dns_msg)?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the config.toml config file")
                .long_help(
"Without [ -o / --odoh ], 
    Client will use target as ODoH API Target to get oDoH Config
    From oDoH Config, it will get oDoH target hostname
    Auth_Token will be used from ODoHConfig Response.
With [ -o / --odoh ],
    Client will use target from config_file as oDoH Target and send oDoH request
    Auth Token needed using Argument [ -a / --auth ]"
                )
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("odohkey")
            .short("k")
            .long("key")
            .value_name("FILE")
            .help("File containing target resolver odoh public key")
            .long_help(
"If target resolver KMI public key file used,
    Client will use target from config_file as oDoH Target and send oDoH request.

Auth_Token required with Argument [ -a / --auth ]"
            )
            .takes_value(true)
            .required(false),
        )
        .arg(
            Arg::with_name("authtoken")
            .short("a")
            .long("auth")
            .help("Auth Token to use to validate ProxyA")
            .long_help(
                "Auth Token is Required if [ -o / --odoh ] argument is used for resolver kem/kdc/aead/public key in binary"
            )
            .takes_value(true)
            .required(false),
        )
        .arg(
            Arg::with_name("domain")
                .short("d")
                .long("domain")
                .help("Domain to query")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("type")
                .short("t")
                .long("type")
                .help("Query type")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .value_name("BOOL")
                .help("True/False for Verbose")
                .default_value("false")
        )
        .get_matches();

    let config_file = matches
        .value_of("config_file")
        .unwrap_or("tests/config.toml");
    let config = Config::from_path(config_file)?;
    let domain = matches.value_of("domain").unwrap();
    let qtype = matches.value_of("type").unwrap();
    let verbose:bool = bool::from_str(matches.value_of("verbose").unwrap()).unwrap();
    let odohkey = matches.value_of("odohkey").unwrap_or("");
    let auth = matches.value_of("authtoken").unwrap_or("");

    let mut session = ClientSession::new(config.clone(), &odohkey, verbose).await?;
    let request = session.create_request(domain, qtype)?;
    let response = session.send_request(&request, &auth).await?;
    session.parse_response(response, verbose).await?;
    Ok(())
}
