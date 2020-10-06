use chrono::prelude::*;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha1::Sha1;
use rand::seq::SliceRandom;

pub fn oauth2_authorization_header(bearer_token: &str) -> String {
    format!("Bearer {}", bearer_token)
}

pub fn oauth1_authorization_header(
    consumer_key: &str,
    consumer_secret: &str,
    access_token: &str,
    access_token_secret: &str,
    method: &str,
    uri: &str,
    options: &Vec<(&str, &str)>,
) -> String {
    let res = calc_oauth_header(
        &format!("{}&{}", consumer_secret, access_token_secret),
        consumer_key,
        &vec![("oauth_token", access_token)],
        method,
        uri,
        options,
    );
    format!("OAuth {}", res)
}

pub fn calc_oauth_header(
    sign_key: &str,
    consumer_key: &str,
    header_options: &Vec<(&str, &str)>,
    method: &str,
    uri: &str,
    options: &Vec<(&str, &str)>,
) -> String {
    let mut param0: Vec<(&str, String)> = vec![
        ("oauth_consumer_key", String::from(consumer_key)),
        ("oauth_nonce", nonce()),
        ("oauth_signature_method", String::from("HMAC-SHA1")),
        ("oauth_timestamp", timestamp()),
        ("oauth_version", String::from("1.0")),
    ];
    for header_option in header_options {
        param0.push((header_option.0, encode(header_option.1)));
    }
    let mut param1 = param0.clone();
    for option in options {
        param1.push((option.0, encode(option.1)));
    }
    param1.sort();
    let parameter = make_query(&param1, "&");
    let base = format!("{}&{}&{}", method, encode(uri), encode(&parameter));
    let mut param2 = param0.clone();
    param2.push(("oauth_signature", encode(&sign(&base, sign_key))));
    make_query(&param2, ", ")
}

const BASE_STR: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn nonce() -> String {
    let mut rng = &mut rand::thread_rng();
    String::from_utf8(
        BASE_STR
            .as_bytes()
            .choose_multiple(&mut rng, 32)
            .cloned()
            .collect(),
    )
    .unwrap()
}

fn timestamp() -> String {
    format!("{}", Utc::now().timestamp())
}

pub fn encode(s: &str) -> String {
    // Twitter API URL encode space is %20 not +
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20").replace('*', "%2A").replace("%7E", "~")
}

fn sign(base: &str, key: &str) -> String {
    let mut hmac = Hmac::new(Sha1::new(), key.as_bytes());
    hmac.input(base.as_bytes());
    base64::encode(hmac.result().code())
}

fn make_query(list: &Vec<(&str, String)>, separator: &str) -> String {
    let mut result = String::from("");
    for item in list {
        if "" != result {
            result.push_str(separator);
        }
        result.push_str(&format!("{}={}", item.0, item.1));
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_oauth2_authorization_header() {
        assert_eq!("Bearer abc", crate::oauth2_authorization_header("abc"));
        println!(
            "{}",
            crate::oauth1_authorization_header(
                "a",
                "b",
                "c",
                "d",
                "GET",
                "http://localhost",
                &vec![]
            )
        );
    }
}
