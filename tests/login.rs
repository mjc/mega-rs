//!
//! Integration test for simply logging in and out of MEGA.
//!

use std::env;

#[tokio::test]
async fn login_and_logout_test() {
    let Ok(email) = env::var("MEGA_EMAIL") else {
        eprintln!("skipping login_and_logout_test: missing MEGA_EMAIL environment variable");
        return;
    };
    let Ok(password) = env::var("MEGA_PASSWORD") else {
        eprintln!("skipping login_and_logout_test: missing MEGA_PASSWORD environment variable");
        return;
    };
    let mfa = env::var("MEGA_MFA").ok();

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, mfa.as_deref())
        .await
        .expect("could not log in to MEGA");

    mega.logout().await.expect("could not log out from MEGA");
}
