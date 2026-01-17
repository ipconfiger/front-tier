// HTTP-01 Challenge Handler for Let's Encrypt domain verification

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::tls::acme_manager::ChallengeData;

/// Handle ACME challenge with shared state
///
/// This is the actual handler that will be registered with the router.
/// It extracts the token from the URL path and returns the key authorization.
///
/// # Arguments
/// * `token` - The challenge token from the URL path
/// * `challenges` - Shared challenge storage from AcmeManager
///
/// # Returns
/// - 200 OK with key_authorization as plain text
/// - 404 Not Found if token doesn't exist
/// - 410 Gone if token has expired
///
/// # HTTP-01 Challenge Flow
/// When Let's Encrypt needs to verify domain ownership via HTTP-01 challenge:
/// 1. ACME manager (in AcmeManager::obtain_certificate) generates token and key_authorization
/// 2. Stores them in shared state (challenges: Arc<RwLock<HashMap<String, ChallengeData>>>)
/// 3. Let's Encrypt makes HTTP request to: `http://{domain}/.well-known/acme-challenge/{token}`
/// 4. This handler responds with key_authorization as plain text
/// 5. Let's Encrypt validates response and completes challenge
///
/// # Integration
/// The challenges Arc<RwLock<HashMap>> is obtained from AcmeManager::challenges()
/// and must be registered with the axum router using:
/// ```rust
/// .route(
///     "/.well-known/acme-challenge/:token",
///     get(tls::handle_acme_challenge)
/// )
/// .with_state(challenges)
/// ```
pub async fn handle_acme_challenge(
    Path(token): Path<String>,
    State(challenges): State<Arc<RwLock<HashMap<String, ChallengeData>>>>,
) -> Response {
    let challenges_guard = challenges.read().await;

    match challenges_guard.get(&token) {
        Some(challenge_data) => {
            // Check if challenge has expired
            if challenge_data.expires_at < Utc::now() {
                info!(
                    "ACME challenge expired for token: {} (domain: {})",
                    token, challenge_data.domain
                );
                return (StatusCode::GONE, "Challenge expired").into_response();
            }

            info!(
                "Serving ACME challenge for token: {} (domain: {})",
                token, challenge_data.domain
            );

            // Return key authorization as plain text with proper content type
            // Use IntoResponse tuple syntax for (status, headers, body)
            let headers = [(axum::http::header::CONTENT_TYPE, "text/plain")];
            (StatusCode::OK, headers, challenge_data.key_auth.clone()).into_response()
        }
        None => {
            info!("ACME challenge not found for token: {}", token);
            (StatusCode::NOT_FOUND, "Challenge not found").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_challenge_data(expires_in_hours: i64) -> ChallengeData {
        ChallengeData {
            token: "test_token".to_string(),
            key_auth: "test_key_authorization".to_string(),
            domain: "example.com".to_string(),
            expires_at: Utc::now() + Duration::hours(expires_in_hours),
        }
    }

    #[tokio::test]
    async fn test_valid_challenge_response() {
        let mut challenges = HashMap::new();
        challenges.insert(
            "test_token".to_string(),
            create_test_challenge_data(1), // Expires in 1 hour
        );

        let challenges_arc = Arc::new(RwLock::new(challenges));

        // Test the handler function
        let response = handle_acme_challenge(
            Path("test_token".to_string()),
            State(challenges_arc),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_expired_challenge_response() {
        let mut challenges = HashMap::new();
        challenges.insert(
            "expired_token".to_string(),
            create_test_challenge_data(-1), // Expired 1 hour ago
        );

        let challenges_arc = Arc::new(RwLock::new(challenges));

        let response = handle_acme_challenge(
            Path("expired_token".to_string()),
            State(challenges_arc),
        )
        .await;

        assert_eq!(response.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn test_missing_challenge_response() {
        let challenges = HashMap::new();
        let challenges_arc = Arc::new(RwLock::new(challenges));

        let response = handle_acme_challenge(
            Path("nonexistent_token".to_string()),
            State(challenges_arc),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_challenge_storage() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));

        // Add a challenge
        let challenge_data = create_test_challenge_data(1);
        challenges
            .write()
            .await
            .insert(challenge_data.token.clone(), challenge_data);

        // Verify it's stored
        let challenges_read = challenges.read().await;
        assert_eq!(challenges_read.len(), 1);
        assert!(challenges_read.contains_key("test_token"));
        assert_eq!(
            challenges_read.get("test_token").unwrap().key_auth,
            "test_key_authorization"
        );
    }

    #[tokio::test]
    async fn test_multiple_challenges() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));

        // Add multiple challenges for different domains
        let challenge1 = ChallengeData {
            token: "token1".to_string(),
            key_auth: "key_auth1".to_string(),
            domain: "example1.com".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
        };

        let challenge2 = ChallengeData {
            token: "token2".to_string(),
            key_auth: "key_auth2".to_string(),
            domain: "example2.com".to_string(),
            expires_at: Utc::now() + Duration::hours(2),
        };

        challenges.write().await.insert(challenge1.token.clone(), challenge1);
        challenges.write().await.insert(challenge2.token.clone(), challenge2);

        // Verify both are stored
        let challenges_read = challenges.read().await;
        assert_eq!(challenges_read.len(), 2);

        // Test handler for each token
        drop(challenges_read);

        let response1 = handle_acme_challenge(
            Path("token1".to_string()),
            State(Arc::clone(&challenges)),
        )
        .await;
        assert_eq!(response1.status(), StatusCode::OK);

        let response2 = handle_acme_challenge(
            Path("token2".to_string()),
            State(challenges),
        )
        .await;
        assert_eq!(response2.status(), StatusCode::OK);
    }
}
