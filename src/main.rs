use aws_lambda_events::event::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use lambda::{Context, Handler};
use rusoto_core::Region;
use rusoto_dynamodb::{
    AttributeValue, DeleteItemInput, DynamoDb, DynamoDbClient, GetItemInput, PutItemInput,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::Digest;
use std::collections::HashMap;
use std::env;
use std::pin;
use thiserror::Error;

#[derive(Serialize, Deserialize)]
struct Vault {
    #[serde(rename = "encryptedVault")]
    encrypted_vault: String,
}

struct HandlerWrapper<'a> {
    handler: &'a SecuboxHandler,
}

impl<'a> Handler<ApiGatewayProxyRequest, ApiGatewayProxyResponse> for HandlerWrapper<'a> {
    type Error = ApiError;
    type Fut = pin::Pin<
        Box<dyn std::future::Future<Output = Result<ApiGatewayProxyResponse, ApiError>> + 'a>,
    >;
    fn call(&mut self, req: ApiGatewayProxyRequest, ctx: Context) -> Self::Fut {
        async fn call(
            handler: &SecuboxHandler,
            req: ApiGatewayProxyRequest,
            ctx: Context,
        ) -> Result<ApiGatewayProxyResponse, ApiError> {
            handler.handle(req, ctx).await
        }
        Box::pin(call(self.handler, req, ctx))
    }
}

struct SecuboxHandler {
    client: DynamoDbClient,
    salt: Vec<u8>,
    vault_table: String,
    #[allow(dead_code)]
    stats_table: String,
}

#[derive(Error, Debug)]
enum ApiError {
    #[error("key not found")]
    KeyNotFound,
    #[error("invalid request")]
    InvalidRequest,
    #[error("json encoding error")]
    SerdeError(#[from] serde_json::Error),
    #[error("base64 encoding error")]
    Base64Error(#[from] base64::DecodeError),
    #[error("dynamodb get error")]
    DynamodbGetError(#[from] rusoto_core::RusotoError<rusoto_dynamodb::GetItemError>),
    #[error("dynamodb put error")]
    DynamodbPutError(#[from] rusoto_core::RusotoError<rusoto_dynamodb::PutItemError>),
    #[error("dynamodb delete error")]
    DynamodbDeleteError(#[from] rusoto_core::RusotoError<rusoto_dynamodb::DeleteItemError>),
}

impl SecuboxHandler {
    async fn handle(
        &self,
        req: ApiGatewayProxyRequest,
        _ctx: Context,
    ) -> Result<ApiGatewayProxyResponse, ApiError> {
        let key: &str = match req.path_parameters.get("key") {
            Some(key) => key,
            None => "",
        };

        if key == "info" {
            return Ok(ApiGatewayProxyResponse {
                status_code: 200,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(
                    json!({
                        "version": "1.0.0",
                        "language": "Rust",
                        "author": "Jeffrey Bolle"
                    })
                    .to_string(),
                ),
                is_base64_encoded: Some(false),
            });
        }

        match self.try_handle(req.http_method.as_deref(), key, req.body).await {
            Ok(resp) => Ok(resp),
            Err(ApiError::InvalidRequest) => Ok(ApiGatewayProxyResponse {
                status_code: 400,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(
                    json!({
                        "error": "Invalid Request",
                    })
                    .to_string(),
                ),
                is_base64_encoded: Some(false),
            }),
            Err(ApiError::KeyNotFound) => Ok(ApiGatewayProxyResponse {
                status_code: 404,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(
                    json!({
                        "error": "Key Not Found",
                    })
                    .to_string(),
                ),
                is_base64_encoded: Some(false),
            }),
            Err(_) => Ok(ApiGatewayProxyResponse {
                status_code: 500,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(
                    json!({
                        "error": "Unknown Error",
                    })
                    .to_string(),
                ),
                is_base64_encoded: Some(false),
            }),
        }
    }

    async fn try_handle(
        &self,
        method: Option<&str>,
        key: &str,
        body: Option<String>,
    ) -> Result<ApiGatewayProxyResponse, ApiError> {
        let storage_key = self.calculate_storage_key(key);
        match method {
            Some("GET") => self.get(&storage_key).await,
            Some("PUT") => self.put(&storage_key, body).await,
            Some("DELETE") => self.delete(&storage_key).await,
            _ => Err(ApiError::InvalidRequest),
        }
    }

    async fn get(&self, storage_key: &str) -> Result<ApiGatewayProxyResponse, ApiError> {
        let vault = self.get_vault(storage_key).await?;
        let body = serde_json::to_string(&Vault {
            encrypted_vault: vault,
        })?;
        Ok(ApiGatewayProxyResponse {
            status_code: 200,
            headers: cors(),
            multi_value_headers: Default::default(),
            body: Some(body),
            is_base64_encoded: Some(false),
        })
    }

    async fn put(
        &self,
        storage_key: &str,
        body: Option<String>,
    ) -> Result<ApiGatewayProxyResponse, ApiError> {
        let body = match body {
            Some(s) => s,
            None => return Err(ApiError::InvalidRequest),
        };
        let vault: Vault = serde_json::from_str(&body)?;
        let mut item = HashMap::new();
        item.insert(
            "StorageKey".to_string(),
            AttributeValue {
                s: Some(storage_key.to_string()),
                ..Default::default()
            },
        );
        item.insert(
            "EncryptedVault".to_string(),
            AttributeValue {
                b: Some(bytes::Bytes::copy_from_slice(
                    base64::decode(vault.encrypted_vault)?.as_slice(),
                )),
                ..Default::default()
            },
        );

        self.client
            .put_item(PutItemInput {
                item,
                table_name: self.vault_table.clone(),
                ..Default::default()
            })
            .await?;

        Ok(ApiGatewayProxyResponse {
            status_code: 204,
            headers: cors(),
            multi_value_headers: Default::default(),
            body: None,
            is_base64_encoded: Some(false),
        })
    }

    async fn delete(&self, storage_key: &str) -> Result<ApiGatewayProxyResponse, ApiError> {
        let mut key = HashMap::new();
        key.insert(
            "StorageKey".to_string(),
            AttributeValue {
                s: Some(storage_key.to_string()),
                ..Default::default()
            },
        );

        self.client
            .delete_item(DeleteItemInput {
                key,
                table_name: self.vault_table.clone(),
                ..Default::default()
            })
            .await?;

        Ok(ApiGatewayProxyResponse {
            status_code: 204,
            headers: cors(),
            multi_value_headers: Default::default(),
            body: None,
            is_base64_encoded: Some(false),
        })
    }

    async fn get_vault(&self, storage_key: &str) -> Result<String, ApiError> {
        let mut key = HashMap::new();
        key.insert(
            "StorageKey".to_string(),
            AttributeValue {
                s: Some(storage_key.to_string()),
                ..Default::default()
            },
        );

        let result = self
            .client
            .get_item(GetItemInput {
                key,
                table_name: self.vault_table.clone(),
                ..Default::default()
            })
            .await;

        if let Ok(result) = result {
            if let Some(item) = result.item {
                if let Some(property) = item.get("EncryptedVault") {
                    if let Some(vault_binary) = &property.b {
                        return Ok(base64::encode(vault_binary));
                    }
                }
            }
        }

        Err(ApiError::KeyNotFound)
    }

    fn calculate_storage_key(&self, key: &str) -> String {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.salt);
        hasher.update(key.as_bytes());
        let digest = hasher.finalize();
        hex::encode(digest.as_slice())
    }
}

fn cors() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(String::from("Access-Control-Allow-Origin"), String::from("*"));
    headers
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let handler = SecuboxHandler {
        client: DynamoDbClient::new(Region::EuWest2),
        salt: hex::decode(env::var("SALT")?)?,
        vault_table: env::var("VAULT_TABLE")?,
        stats_table: env::var("STATS_TABLE")?,
    };
    lambda::run(HandlerWrapper { handler: &handler }).await?;
    Ok(())
}
