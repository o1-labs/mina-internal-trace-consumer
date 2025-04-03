use crate::authentication::{Authenticator, BasicAuthenticator, SequentialAuthenticator};
use crate::graphql;
use crate::InternalLogsQueryInternalLogs;
use crate::graphql::schedule_zkapp_commands_query::ZkappCommandsDetails;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use graphql_client::GraphQLQuery;
use std::convert::From;
use std::env;
use tracing::{error, info, instrument};

#[derive(Default, Clone)]
pub struct AuthorizationInfo {
    pub(crate) server_uuid: String,
    pub(crate) signer_sequence_number: u16,
}

pub struct MinaClientConfig {
    pub address: String,
    pub graphql_port: u16,
    pub use_https: bool,
    pub secret_key_base64: String,
}

impl MinaClientConfig {
    pub fn graphql_uri(&self) -> String {
        let schema = if self.use_https { "https" } else { "http" };
        format!("{}://{}:{}/graphql", schema, self.address, self.graphql_port)
    }
}

pub struct MinaGraphQLClient {
    pub(crate) config: MinaClientConfig,
    pub(crate) keypair: ed25519_dalek::Keypair,
    pub(crate) pk_base64: String,
    pub(crate) last_log_id: i64,
    pub(crate) authorization_info: Option<AuthorizationInfo>,
}

impl From<MinaClientConfig> for MinaGraphQLClient {
    fn from(config: MinaClientConfig) -> Self {
        let sk_bytes = general_purpose::STANDARD
            .decode(config.secret_key_base64.trim_end())
            .expect("Failed to decode base64 secret key");
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&sk_bytes)
            .expect("Failed to interpret secret key bytes");
        let public_key: ed25519_dalek::PublicKey = (&secret_key).into();
        let keypair = ed25519_dalek::Keypair {
            secret: secret_key,
            public: public_key,
        };
        let pk_base64 = general_purpose::STANDARD.encode(keypair.public.as_bytes());
        Self {
            config,
            keypair,
            pk_base64,
            last_log_id: 0,
            authorization_info: None,
        }
    }
}

impl MinaGraphQLClient {
    pub async fn authorize(&mut self) -> Result<()> {
        let auth = self.perform_auth_query().await?;
        self.authorization_info = Some(AuthorizationInfo {
            server_uuid: auth.server_uuid,
            signer_sequence_number: auth.signer_sequence_number.parse()?,
        });
        Ok(())
    }

    pub async fn fetch_more_logs(&mut self) -> Result<(bool,Vec<InternalLogsQueryInternalLogs>)> {
        let prev_last_log_id = self.last_log_id;
        let (last_log_id, logs) = self.perform_fetch_internal_logs_query().await?;
        self.last_log_id = last_log_id;
        if let Some(auth_info) = &mut self.authorization_info {
            auth_info.signer_sequence_number += 1;
        }

        Ok((prev_last_log_id < self.last_log_id,logs))
    }

    pub async fn flush_logs(&mut self) -> Result<()> {
        self.perform_flush_internal_logs_query().await?;
        if let Some(auth_info) = &mut self.authorization_info {
            auth_info.signer_sequence_number += 1;
        }

        Ok(())
    }

    pub async fn run_query_unsafe(
        &self,
        query: &str,
    ) -> Result<String> {
        let client = reqwest::Client::new();
        let body_bytes = serde_json::to_vec(query).map_err(|e| anyhow!("Invalid JSON query: {}", e))?;
        let signature_header = SequentialAuthenticator::signature_header(self, &body_bytes)?;
        let response = client
            .post(&self.config.graphql_uri())
            .json(&query)
            .header(reqwest::header::AUTHORIZATION, signature_header)
            .header(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"))
            .send()
            .await?;

        println!("DEBUG RESPONSE: {:#?}", response);
        Ok(response.text().await?)
    }

    pub fn get_signature(&self, body: &str) -> Result<String> {
        let body_bytes = serde_json::to_vec(body)?;
        let signature_header = SequentialAuthenticator::signature_header(self, &body_bytes)?;
        Ok(signature_header)
    }

    async fn post_graphql<Q: GraphQLQuery, A: Authenticator>(
        &self,
        client: &reqwest::Client,
        variables: Q::Variables,
    ) -> Result<graphql_client::Response<Q::ResponseData>> {
        let body = Q::build_query(variables);
        let body_bytes = serde_json::to_vec(&body)?;
        let signature_header = A::signature_header(self, &body_bytes)?;
        let response = client
            .post(&self.config.graphql_uri())
            .json(&body)
            .header(reqwest::header::AUTHORIZATION, signature_header)
            .send()
            .await?;

        println!("DEBUG RESPONSE: {:#?}", response);
        Ok(response.json().await?)
    }

    pub async fn reset_zkapp_soft_limit_query(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::reset_zkapp_soft_limit_query::Variables { };
        let _response = self
            .post_graphql::<graphql::ResetZkappSoftLimitQuery, BasicAuthenticator>(&client, variables)
            .await?;
        Ok(())
    }

    pub async fn schedule_zkapp_payments(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::schedule_zkapp_commands_query::Variables { 

            input: ZkappCommandsDetails {
                max_account_updates: 2,
                max_cost: true,
            
                account_queue_size: 0,
            
                deployment_fee: 1000000000,
            
                max_fee: 2000000000,
            
                min_fee: 1000000000,
            
                init_balance: 6000360000,
            
                max_new_zkapp_balance: 3000180000,
            
                min_new_zkapp_balance: 1000060000,
            
                max_balance_change: 1000,
            
                min_balance_change: 0,
            
                no_precondition: false,
            
                memo_prefix: "sync_frontier_comparision_more_zkapps_12-0-0".to_string(),
            
                duration_min: 30,
            
                tps: 0.2553061739602372,
            
                num_new_accounts: 0,
            
                num_zkapps_to_deploy: 8,
            
                fee_payers: vec!["EKEMrs8vC3mY9YeGdGz1zTmp66gtZrDT1pUdGRgbAHBczHZ1LTvS".to_string(),
                "EKE9jfZ7EmzeYCKuNM58J2UNTt2T4DcyDAFYL8pyQz3U6fy7uqLJ".to_string(),
                "EKECxefrJwiQfiS7agJEVLs762gusXjiom7S3yveR9rN5vT7AGrV".to_string(),
                "EKESFmrZZdBiBA7yHmZgBCS4As8CVA3jGDWGKiu7VjSbUaFNJNdy".to_string(),
                "EKEEknCLGn89RLQtLn8A1de8LQSfzpHxybR8wktFvT5kwaj5LFbN".to_string(),
                "EKERuNXwqdJK9xYfhEiZyeMedqvt433Y5nEohktj1S6B4DN7yvTu".to_string(),
                "EKDi6rJNu9eGUn3MmdzJNYzA7TQMMym3h2YdNcTwvywgseH8ub21".to_string(),
                "EKEbvRs7HX5y6hWzYzorF314EXYr4DQy6xopnEW4hXjnik8KzJZj".to_string(),
                "EKE3uJDkR84P4q1hmxVZZCySxLDfYfVX3f7eAY55jiPUc2nHP44C".to_string(),
                "EKEhtRV9AHBBS3thsP4ALya6QHx9tsMB5ix1iVYvMpxkUALBVyZ6".to_string(),
                "EKEGj63daM2aF9XoVmhq9SzxFvKnNwNhyfnUiGvEhhzSv9aJJ9NW".to_string(),
                "EKEWwkD8gFGtjL6pH85MqZ9YBs3UPBMW6BPT4AUJV4kwe9hRsc9C".to_string(),
                "EKFLLtFFSDf5X2ceRKNYKvgSi7dALh3V43UzP4hoUnvnEgnTigN4".to_string(),
                "EKFNz1mG3MRzsBY6tgp98avfwSQHijW3Lp1XybxGAGnBgwx5rgk5".to_string(),
                "EKEL4NE8Mxnc2coyn98AooezgkxWn3HSpMSRC2MisHxuf2fMYoYM".to_string(),
                "EKFJqZjFKXGNhrgJD6xhATYnqhr3jwKaoptFWVsmdrTKb1rZJaGJ".to_string(),
                "EKFYg6b2zXPU8R8wM47G8sH17QdTASG1fdgTFdnoXgu9LxutufWo".to_string(),
                "EKFB4wR9pUUsofbRD4KHnegS5Rw9rBaMjvtKqTWJ4EqfQLKvrVDz".to_string(),
                "EKEBBDoeh3nENHYDxLqtYGtXm5ongh55vpGe8vYFLsEAci2X1zXs".to_string(),
                "EKEgzdormVot3xnDNwDko81d7cMrb1jS2NWwVtzD2q8msoQmbDeM".to_string(),
                "EKFMykeAgcr7Q5NayrPMYWH4fD2ep69WPNLJiFyJhCPwGpSxrguD".to_string(),
                "EKEHg6SBaBG9ApEn1x74mmLx2CNC9xrL5YrrsKhCaES2X3am4DeS".to_string(),
                "EKF24S1kYJMXzyMDLKs3qs3uKbiJ7M599gnjDhCup49KoUy7Dpfx".to_string(),
                "EKEzAzCGEz73X6L66mJdda9bAATSiFTp6dwYrfPMbpx8rzVGYtnA".to_string(),
                "EKEegHfmbPzsZ7JGu1PKh4Bb2eTKYDsQa33CiiYZnkTgBWQBsQ6n".to_string(),
                "EKFa1gBGcGzDjiDuLqQgzPKgfBB6LpiKn814PePza7XvZZ1Z5xGQ".to_string(),
                "EKFKmVa9sig28cyeBTDnLafuF7DHL4eAY1DnhshG9LY4hW98D4NS".to_string(),
                "EKDrNeUpizYHpzzbPy3Vjfs22VVVfkDfvPUHycPM6wd87QkUPSzd".to_string(),
                "EKE27GjtrQoB2ATG3eNzKXZqFUXWeNN5RwjvKzS4aVoUoch9hYEN".to_string(),
                "EKECj7BGkhvvfrajz8QY5DKnGPiMpyw86VUYCpccZmhpSXjQbqQk".to_string(),
                "EKFPzNGLLJHgnQaoeED6upfEjecxaDC4MT4DDd4gBC5YjQV5cfcp".to_string(),
                "EKENK5XRkDxsME2aDshZQfatnmaKbyEBwAY9L4WsDUNbEJbjb9tW".to_string(),
                "EKEZza2qCe2gM1FCC7TTfnvuzHZwnt59HtWXjHpSYgug4VUj4KjZ".to_string(),
                "EKFM2oXu7yRtPfsTN5DWXEuEaiXtqkgofKeD4twKsfkV9JwMPPVi".to_string(),
                "EKFKKhz3EgeBSWfEQkvXpJobUy3gQqkE335VCEqS7TpwTdibk99h".to_string(),
                "EKEt8v4zWg4VTPD8cHg1YGctq6ynDiBqBLY3Haywaov3ttiRWojQ".to_string(),
                "EKEwFnFHZFqf6VHQm43qBoUXf42wsy74DLgLsj9QFBFUftb6ZPxf".to_string(),
                "EKF4AX6aZFXHA8WDexDM8RMMHNGyYf8rTam7dYcwxYJJsez5hLYo".to_string(),
                "EKDrNw6AVCPbYm6T5Ys7kX7NKkycosfk5fWh5fonLmW1UWePKcB9".to_string(),
                "EKEiY1VsxqiHmmj2dv2BodcY3DTk2fxSwUEZxWura1EaNNTJ8WAv".to_string(),
                "EKDrJi1LP5Aq4AzTZqnVNDnbnG3jbsZR3tsRPVyKbWuHmjAZrK9V".to_string(),
                "EKFcYVMch2i8Ccon9RmQHNtbqW34VC9dddtaNmwxo1G1UxwdHPtr".to_string(),
                "EKEFtNsY3cR5G4nNp19p7LYoRpFFGJ8UzfbVCLc7WXDd8mPaJSX6".to_string(),
                "EKFPGmbWmdC1Bob98D9GodWTX7igfSTD8RoymHYKmEwdUaSWuo2S".to_string(),
                "EKDySKCvnGG1WV27eSnpBeykPnChHCuveuACW73qYiE28xqDCJbw".to_string(),
                "EKDxfAUwTGVvmRA6CFSkJLDAU9Bpesov1ETWfB7ynuiH8f6ueS7B".to_string(),
                "EKEaoctr2EaUX28iHHLPFJPEXDHJ4CWQoG6EHxXtrnb7k5CMTaFq".to_string(),
                "EKE7CQxfomFe9VUTiTQ652LnyJiwGUG59hBHCLUVLC5aVNLztsCN".to_string(),
                "EKE8JqqzniUZNrqJUvnhFf9Q26adsVyqppSCjbiUXoC9nVk3kerX".to_string(),
                "EKFZVu6mh98W2aWiy1tgfZzRSrsWGYhiAkychusUNg9ahPuDBy7t".to_string(),
                "EKFVW8Z4jA9Qt5DfcmvZobayLToPj2wQPSc2846n3nYjLU7Cz9oB".to_string(),
                "EKF2wQAKSv55LXYnxY7TSvsNme2YdSFRQbkDCHeajYyFZbajm4K1".to_string(),
                "EKEjnJgbJSCp1kCFWnHNdfBGryvcSnwd6JxNQ1Tj9ebL5fHSL3in".to_string(),
                "EKE5N7274Hx1V2nkSMA36Lx2faCNUoZkg1D9jy9R9cnAgKxv8kVD".to_string(),
                "EKDyMhft4AZ2KcdNynczcKZ2EKaJEwputs37BfuJXjJ8YZ2bvydr".to_string(),
                "EKE6LbG4NAGFF7pAn9i4BTkT2duHNoXXWHHYyriuusrGFqbSNN8f".to_string(),
                "EKFD2fS46vfdeSNnYiDUJcCQ1VSeGeMKH38nSDGGo4WiDpiFQ36y".to_string(),
                "EKDxcMHWv2psb9Ra46s4FDA8CvscnEzu44Bqpy42pBjwW1nHeuUg".to_string(),
                "EKF1rEeAMT1Xdx8uRqVTbuzZSEv8d83RF8QzVEWaVLkkLzNrkoUv".to_string(),
                "EKEctAYZywPyNsTzquaeS9SsUFk3raLfkse2k4YDMuuPjnALevU1".to_string(),
                "EKFDaZDKZdQqnkjHPz5RvKuE3amyE1BSeuUpP6uq6VQ44ebbgSFv".to_string(),
                "EKDy6sLjBEX2i2Hc2gjAGR8eGqzzBxVvZht5gQ1QmAchPhQn46Zy".to_string(),
                "EKERr5KuW36sB3UvgMNbQtz8X5FuXUQxjV44JApaXVCrtFTRZLEY".to_string(),
                "EKESmACrcexBwathDHYMcnwQyEUDadBg1zEYn63EZ49q1j7Mrv2y".to_string(),
                "EKEENWdaZyoewwAYjqih3UbqPBuQnftv2wPqTU3VnuJLByj1Sbut".to_string(),
                "EKEiYvfFrcMcqamqmDJ2b19rMLxbKf3ucgcg91GGZ2aAwaaUeCRo".to_string(),
                "EKE95ewyDNvACkaUVhvYY5SrYtyJFvkPg1YSq98pwgjWenpMTrUX".to_string(),
                "EKE9kWyvbNtFEFfR2DKmM5Moti5f1cojBtzJJadxYxxoPC91kEeS".to_string(),
                "EKERxkRf8u2XmtuHSmRWKKV2QKTVLBxyoyp3JddK2Me6Sz44Vb5c".to_string(),
                "EKFAkbZQSG1daW8ZCGc95B2yh5snEAuRkjwPytoXKER6P5fKGJw5".to_string(),
                "EKEcAcdebczyEyV3k6sv6gtyUuPS7FnnU4HnrtzwyZwFxb1aGDvk".to_string(),
                "EKFA59XWkbiZFg9LyLSJ5N9xTSHiCvhAmVh78MUazPNGKmUxsJs5".to_string(),
                "EKFCbXxSUeQMY2fNQtMvkGG9wMuC4fo66CbYsu5XoWkFgARkQgWj".to_string(),
                "EKEFaiBeDtx2wyDtpDye1UrQY64bJkm8muwASA9Cq15uZLtZ9BJg".to_string(),
                "EKEdKJ8UGtDUxFS5qq6XqJJYGmuaT2t25Gf13AVPXzFM9DA5AQpq".to_string(),
                "EKELpJYvxWZgKFPAVTSEJ4J1EddKx9iJNDraPQQ4Rf82H5YNKd45".to_string(),
                "EKELzL8yhEwMs5nobTBcf7CpVf9kk3878LQtBe5hEKjNbmhdghCs".to_string(),
                "EKEkocZ4svoBxk9U91C2n2y6wUZWH8DWHc4wymkLQcPWMPTQZ7PP".to_string(),
                "EKFdpVLskitjt6K7W9Cf3qDWrykoWzTY5XiN7UoHBx5dLU8qogHc".to_string(),
                "EKFZsdXcDgoae4Ygz5jzqAdTT9i7mkEeqUZZVegKQwrXwaJkqKPg".to_string(),
                "EKEhM2ih76ffgYa2VyhSJxLukJo6eGo1Q2UmcP1rGwUxa2EwrAd1".to_string(),
                "EKEgyTvre8txzCEb1b1nJbXLQgvjWLNLNB6MnzM9maqB7G4TuyZK".to_string(),
                "EKDoq95BpbT4T6VFDxDrxiKrYVUoeX1F1oGfNoZh19oUsApEFeA6".to_string(),
                "EKFa34SbNpt2EGTesTdUQeobMeH5LS4XrZBZQHimLM7h6rpQQXXL".to_string(),
                "EKEY5Z7UYxpT51Lp4BTyQNb3vKK6asCYsE2Y9so1v7YYjwfG1J6i".to_string(),
                "EKDirgx2b4h1gwKYKtT77c3H1Ejb3vZ49qD8GKqRLa65x2Jq1zLd".to_string(),
                "EKFYmHMsXQJRiGc8EAGvXdw2cqkMxjBQRREFU11wiTgzmZHVuC2U".to_string(),
                "EKEHNtxk5oiuP5KYkwK6EZ8K19sZ4eA1rDWfGfRfVpy2i8act91V".to_string(),
                "EKEMcrpQcM5WdaXwjUiGVkUuc4ArquY3f9QuycVwDjvXj47uHQYx".to_string(),
                "EKFCQE6hEdsW31TruShJTF5ttnQvAPco7UbsPW8KvSJ51FPr21gZ".to_string(),
                "EKEFPNtTbbgt9DvUCt2NaaWgfm1wzAHzQBXL8WagpFS3NzN595gM".to_string(),
                "EKFdb8kU2n2cqbAcmGi23SYPh7K3jqWy8Fkq1UVm6ZJajFpu3tu6".to_string(),
                "EKFAzatPmNxheRPZcrudEB8h1M4CYRfFSYVun2PC6yiFYr5jyrWw".to_string(),
                "EKEYG7itG3bR2kvW22aeFzekNnfFZfdy7TGUhYqn1kh8TtF6FhVC".to_string(),
                "EKExSYQfc9Brtqj4WpAHb6KWyDksAPXutWAqozSCogifqyKDgvFQ".to_string(),
                "EKEuy3tsyPvYNBwRr458GSEneoMR49QD6ELxKcu85Q7FcGg3dFRb".to_string(),
                "EKF5VZfExJBzPtkizNXrXFn71kzw5w3a2sCcesYgzZFQ6bvtyg4U".to_string(),
                "EKDzyiPwDmUiYZEP6j2ALzt14oSGx7ZyYAbtpWDL9FPg58pMvUyq".to_string(),
                "EKFdNUAakJc19FagvG2QUFnbSn1eqZYEhfvngbtvmtjW9SfgR5ny".to_string(),
                "EKFSVGEw5LCNY2eUebVGK57J9m7DvJPEF7WJGzeeLgiHnPQEWa4A".to_string(),
                "EKEKq7XABj2nT2AgkHu2nbhsr8mV9Ua2SCc2KXFvtLPEWAPqHytZ".to_string(),
                "EKFJynCPiP9MuE2Vyd9rSFeqc8cnwERJPj6iwxk72fWikTXzMuh2".to_string(),
                "EKF1kPjhuR4Qh48poikwTgg4rvMnyYjfQiRAoaFQftU1ffLnsFoj".to_string(),
                "EKEaXaQrkZF6JoM58CTj1acRid2EK4YuEvSPWuXG42ukqE8rwrd3".to_string(),
                "EKEuEDS1cKZba7bgEDwWtaVeyH9LrDssWcP3jMF1jGEdDc1Koa2y".to_string(),
                "EKF28LDD7A5o9KzLKfXcdc2aQLDuVG6thby7zpaiuGsyrcHw6jSs".to_string(),
                "EKFWWSyGaQDYDUPrvCE8CU2RSg2hiK9v2fQWYdiRLh7N7qJPEBDS".to_string(),
                "EKEsiHHbfRZmKiiQ5RZz14UQJRmNKPztZeBaZpkVLM1sFaNPz5vq".to_string(),
                "EKDzwZ3ApsVoaTBHLq88bW2cKLzDxdXCYHYDndqudJYxWidhop2j".to_string(),
                "EKFAQstj1bzwTBLAc9fHqKGuakqvhBaU9EqtChGiARJYpg1yACnm".to_string(),
                "EKFUQdoMa7D7CcLKMDmsGememwMfaFeWZdh7k8bCisnUAaWvkwHa".to_string(),
                "EKEP2xNAxS28JMnMPecDTza4ofQcUsJvwfGJXcH7aBYpWrU2pM5S".to_string(),
                "EKE6T7B38wgMddWhmTF4RURXGFZ1jrz6H3nVg4Tad3UBGkX2GaiT".to_string(),
                "EKFZ6jZ8gWgHMduuTcvnGCyszvbvoPCWLMKvxjy49Af68TLzQdWA".to_string(),
                "EKDwmbzJxh3fxXENAKX6Kmqbo4pw4bjmhjVgAFspCjXEjheGZDG6".to_string(),
                "EKFDaQ35JWML3bSYJ8JYXxYPip2ZZfeR2DCe5XA1s74k39KKCx9J".to_string(),
                "EKEcM59frVuQrx5GWn5StN2Xsm8dXHf6tg9hXj2NCXqXutwXA7qP".to_string(),
                "EKEUMUpxKqGFjfzMVUTiThwmYCvL2pUYcpejHTSvnR8wGiANgtvN".to_string()
                ]
            }
        };
        let _response = self
            .post_graphql::<graphql::ScheduleZkappCommandsQuery, BasicAuthenticator>(&client, variables)
            .await?;
        Ok(())
    }

    async fn perform_auth_query(&self) -> Result<graphql::auth_query::AuthQueryAuth> {
        let client = reqwest::Client::new();
        let variables = graphql::auth_query::Variables {};
        let response = self
            .post_graphql::<graphql::AuthQuery, BasicAuthenticator>(&client, variables)
            .await?;
        let auth = response
            .data
            .ok_or_else(|| anyhow!("Response data is missing"))?
            .auth;
        Ok(auth)
    }

    async fn perform_fetch_internal_logs_query(
        &mut self,
    ) -> Result<(i64, Vec<InternalLogsQueryInternalLogs>)> {
        let client = reqwest::Client::new();
        let variables = graphql::internal_logs_query::Variables {
            log_id: self.last_log_id,
        };
        let response = self
            .post_graphql::<graphql::InternalLogsQuery, SequentialAuthenticator>(&client, variables)
            .await?;
        let response_data = response
            .data
            .ok_or_else(|| anyhow!("Response data is missing"))?;

        let mut last_log_id = self.last_log_id;

        if let Some(last) = response_data.internal_logs.last() {
            last_log_id = last.id;
        }

        Ok((last_log_id, response_data.internal_logs))
    }

    async fn perform_flush_internal_logs_query(&self) -> Result<()> {
        let client = reqwest::Client::new();
        let variables = graphql::flush_internal_logs_query::Variables {
            log_id: self.last_log_id,
        };
        let response = self
            .post_graphql::<graphql::FlushInternalLogsQuery, SequentialAuthenticator>(
                &client, variables,
            )
            .await?;
        let _response_data = response.data.unwrap();
        Ok(())
    }

    #[instrument(
        skip(self),
        fields(
            node = %self.config.graphql_uri()
        ),
    )]
    pub async fn authorize_and_run_fetch_loop(
        &mut self
    ) -> Result<()> {
        match self.authorize().await {
            Ok(()) => info!("Authorization Successful"),
            Err(e) => {
                error!("Authorization failed for node: {}", e);
                Err(e)?
            }
        }

        let mut remaining_retries = 5;

        loop {
            match self.fetch_more_logs().await {
                Ok((true,_)) => {
                    // TODO: make this configurable? we don't want to do it by default
                    // because we may have many replicas of the discovery+fetcher service running
                    if false {
                        self.flush_logs().await?;
                    }
                    remaining_retries = 5
                }
                Ok((false,_)) => remaining_retries = 5,
                Err(error) => {
                    error!("Error when fetching logs {error}");
                    remaining_retries -= 1;

                    if remaining_retries <= 0 {
                        error!("Finishing fetcher loop");
                        return Err(error);
                    }
                }
            }
            let fetch_interval_ms = env::var("FETCH_INTERVAL_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(10000);

            tokio::time::sleep(std::time::Duration::from_millis(fetch_interval_ms)).await;
        }
    }
}
