use crate::error::{AuthError, Result};

/// 邮箱格式校验。
///
/// 刻意保持保守：只拒绝明显不合法的输入（缺 `@`、缺域名点、含空白），
/// 真正的可达性由验证邮件确认。
pub fn validate_email(email: &str) -> Result<String> {
    let email = email.trim();

    if email.is_empty() {
        return Err(AuthError::ValidationError("Email is required".to_string()));
    }
    if email.len() > 254 {
        return Err(AuthError::ValidationError(
            "Email is too long".to_string(),
        ));
    }
    if email.chars().any(|ch| ch.is_whitespace()) {
        return Err(AuthError::ValidationError(
            "Email must not contain whitespace".to_string(),
        ));
    }

    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| AuthError::ValidationError("Email must contain '@'".to_string()))?;

    if local.is_empty() || domain.is_empty() {
        return Err(AuthError::ValidationError(
            "Email is not a valid address".to_string(),
        ));
    }
    if domain.contains('@') {
        return Err(AuthError::ValidationError(
            "Email must contain exactly one '@'".to_string(),
        ));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(AuthError::ValidationError(
            "Email domain is not valid".to_string(),
        ));
    }

    Ok(email.to_ascii_lowercase())
}

/// 密码强度校验：长度 + 至少三类字符（大写 / 小写 / 数字 / 符号）。
pub fn validate_password(password: &str, min_length: usize) -> Result<()> {
    if password.len() < min_length {
        return Err(AuthError::ValidationError(format!(
            "Password must be at least {min_length} characters long"
        )));
    }
    // argon2 本身没有长度上限，但超长输入只会浪费 CPU，这里挡一下。
    if password.len() > 1024 {
        return Err(AuthError::ValidationError(
            "Password must be at most 1024 characters long".to_string(),
        ));
    }

    let has_lower = password.chars().any(|ch| ch.is_lowercase());
    let has_upper = password.chars().any(|ch| ch.is_uppercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|ch| !ch.is_alphanumeric() && !ch.is_whitespace());

    let classes = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    if classes < 3 {
        return Err(AuthError::ValidationError(
            "Password must contain at least three of: lowercase, uppercase, digit, symbol"
                .to_string(),
        ));
    }

    Ok(())
}

/// 用户名校验：长度 3~32，仅允许字母数字、下划线与连字符。
pub fn validate_username(username: &str) -> Result<String> {
    let username = username.trim();

    if username.len() < 3 || username.len() > 32 {
        return Err(AuthError::ValidationError(
            "Username must be between 3 and 32 characters".to_string(),
        ));
    }
    if !username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(AuthError::ValidationError(
            "Username may only contain letters, digits, '_' and '-'".to_string(),
        ));
    }

    Ok(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_email_and_lowercases_it() {
        assert_eq!(validate_email(" User@Example.COM ").unwrap(), "user@example.com");
    }

    #[test]
    fn rejects_malformed_emails() {
        for bad in ["", "no-at-sign", "a@b", "a@@b.com", "a b@example.com", "a@.com"] {
            assert!(validate_email(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn rejects_short_or_low_entropy_passwords() {
        assert!(validate_password("Short1!", 12).is_err());
        assert!(validate_password("alllowercaseletters", 12).is_err());
        assert!(validate_password("alllowercase12345678", 12).is_err());
    }

    #[test]
    fn accepts_password_with_three_character_classes() {
        assert!(validate_password("CorrectHorse42", 12).is_ok());
        assert!(validate_password("correct-horse-42", 12).is_ok());
    }

    #[test]
    fn validates_username_charset_and_length() {
        assert_eq!(validate_username(" alice_01 ").unwrap(), "alice_01");
        assert!(validate_username("ab").is_err());
        assert!(validate_username("bad name").is_err());
    }
}
