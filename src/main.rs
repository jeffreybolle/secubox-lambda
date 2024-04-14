use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use aws_lambda_events::encodings::Body;
use aws_lambda_events::event::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_lambda_events::http::{HeaderMap, HeaderName};
use base64::prelude::*;
use lambda_runtime::{service_fn, LambdaEvent};
use rusoto_core::Region;
use rusoto_dynamodb::{
    AttributeValue, DeleteItemInput, DynamoDb, DynamoDbClient, GetItemInput, PutItemInput,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::Digest;
use thiserror::Error;

#[derive(Serialize, Deserialize)]
struct Vault {
    #[serde(rename = "encryptedVault")]
    encrypted_vault: String,
}

struct SecuboxService {
    client: DynamoDbClient,
    salt: Vec<u8>,
    vault_table: String,
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

impl SecuboxService {
    async fn handle(
        &self,
        req: ApiGatewayProxyRequest,
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
                body: Some(Body::Text(
                    json!({
                        "version": "1.0.2",
                        "language": "Rust",
                        "author": "Jeffrey Bolle"
                    })
                    .to_string(),
                )),
                is_base64_encoded: false,
            });
        }

        match self
            .try_handle(req.http_method.as_str(), key, req.body)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(ApiError::InvalidRequest) => Ok(ApiGatewayProxyResponse {
                status_code: 400,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(Body::Text(
                    json!({
                        "error": "Invalid Request",
                    })
                    .to_string(),
                )),
                is_base64_encoded: false,
            }),
            Err(ApiError::KeyNotFound) => Ok(ApiGatewayProxyResponse {
                status_code: 404,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(Body::Text(
                    json!({
                        "error": "Key Not Found",
                    })
                    .to_string(),
                )),
                is_base64_encoded: false,
            }),
            Err(_) => Ok(ApiGatewayProxyResponse {
                status_code: 500,
                headers: cors(),
                multi_value_headers: Default::default(),
                body: Some(Body::Text(
                    json!({
                        "error": "Unknown Error",
                    })
                    .to_string(),
                )),
                is_base64_encoded: false,
            }),
        }
    }

    async fn try_handle(
        &self,
        method: &str,
        key: &str,
        body: Option<String>,
    ) -> Result<ApiGatewayProxyResponse, ApiError> {
        let storage_key = self.calculate_storage_key(key);
        match method {
            "GET" => self.get(&storage_key).await,
            "PUT" => self.put(&storage_key, body).await,
            "DELETE" => self.delete(&storage_key).await,
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
            body: Some(Body::Text(body)),
            is_base64_encoded: false,
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
                    BASE64_STANDARD
                        .decode(vault.encrypted_vault.as_bytes())?
                        .as_slice(),
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
            is_base64_encoded: false,
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
            is_base64_encoded: false,
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
                        return Ok(BASE64_STANDARD.encode(vault_binary));
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

fn cors() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert::<HeaderName>(
        "Access-Control-Allow-Origin".try_into().unwrap(),
        "*".try_into().unwrap(),
    );
    headers
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let service = Arc::new(SecuboxService {
        client: DynamoDbClient::new(Region::EuWest2),
        salt: hex::decode(env::var("SALT")?)?,
        vault_table: env::var("VAULT_TABLE")?,
    });

    lambda_runtime::run(service_fn(
        move |event: LambdaEvent<ApiGatewayProxyRequest>| {
            let service = Arc::clone(&service);
            async move { service.handle(event.payload).await }
        },
    ))
    .await?;

    Ok(())
}
