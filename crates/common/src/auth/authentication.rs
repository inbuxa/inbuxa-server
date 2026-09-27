/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    Server,
    auth::{
        AccessToken, AuthRequest, DomainCache,
        credential::{ApiKey, AppPassword},
        oauth::{GrantType, token::TOKEN_HEADER},
    },
};
use base64::{Engine, engine::general_purpose};
use directory::{
    Credentials, Directory, Recipient,
    core::secret::{SecretVerificationResult, verify_mfa_secret_hash, verify_secret_hash},
};
use registry::schema::{
    enums::Permission,
    structs::{self, Credential},
};
use serde::Deserialize;
use std::{borrow::Cow, net::IpAddr, sync::Arc};
use store::write::now;
use inbuxa_features::audit::Via;
use trc::AddContext;

pub struct UsernameParts {
    pub account: Username,
    pub master_user: Option<Username>,
}

#[derive(PartialEq, Eq)]
pub struct Username {
    pub name: String,
    pub domain_start: usize,
}

impl Server {
    pub async fn authenticate(&self, req: &AuthRequest) -> trc::Result<AccessToken> {
        match Box::pin(self.route_auth_request(req))
            .await
            // inbuxa: AL-2: a locked account fails as a wrong password does,
            // so the right password learns nothing; master and recovery
            // sign-ins as it fail the same way
            .and_then(|token| {
                if token.is_locked() {
                    Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountId, token.account_id())
                        .reason("Account is locked"))
                } else {
                    Ok(token)
                }
            })
            .and_then(|token| token.assert_has_permission(Permission::Authenticate))
        {
            Ok(token) => {
                // inbuxa: AU-1.4, AU-1.5
                self.audit_sign_in(req, &token).await;
                Ok(token)
            }
            Err(err) => {
                // inbuxa: AU-1.4
                if matches!(err.as_ref(), trc::EventType::Auth(trc::AuthEvent::Failed)) {
                    self.audit_sign_in_failed(req).await;
                }

                // Random delay to mitigate user enumeration attacks
                #[cfg(not(feature = "test_mode"))]
                {
                    use store::rand::{self, RngExt};

                    let delay = rand::rng().random_range(50..500);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                if matches!(
                    err.as_ref(),
                    trc::EventType::Auth(trc::AuthEvent::Failed)
                        | trc::EventType::Security(trc::SecurityEvent::IpUnauthorized)
                ) && self.has_auth_fail2ban()
                    && self
                        .is_auth_fail2banned(req.remote_ip, req.username())
                        .await?
                {
                    Err(trc::SecurityEvent::AuthenticationBan
                        .into_err()
                        .ctx(trc::Key::RemoteIp, req.remote_ip)
                        .ctx_opt(trc::Key::AccountName, req.username().map(|s| s.to_string())))
                } else {
                    Err(err.ctx(trc::Key::RemoteIp, req.remote_ip))
                }
            }
        }
    }

    async fn route_auth_request(&self, req: &AuthRequest) -> trc::Result<AccessToken> {
        match &req.credentials {
            Credentials::Basic {
                username,
                secret,
                mfa_token,
            } => {
                let mut username = UsernameParts::new(username);

                // Try to authenticate as fallback admin if configured
                if let Some((fallback_user, fallback_hash)) = &self.registry().recovery_admin()
                    && username.auth_as().address() == fallback_user
                {
                    return if verify_secret_hash(fallback_hash, secret.as_bytes()).await? {
                        if username.is_master() {
                            let address = username.account().address();
                            if let Some(account_id) =
                                self.impersonated_account_id(username.account()).await?
                            {
                                trc::event!(
                                    Auth(trc::AuthEvent::Success),
                                    AccountName = address.to_string(),
                                    AccountId = account_id,
                                    SpanId = req.session_id,
                                    Details = fallback_user.to_string(),
                                );

                                self.access_token(account_id)
                                    .await
                                    .and_then(|token| AccessToken::new(token, req.remote_ip))
                                    // inbuxa: AU-1.5, AU-5
                                    .map(|token| {
                                        token.with_origin(Via::Master {
                                            account_id: None,
                                            name: fallback_user.to_string(),
                                        })
                                    })
                            } else {
                                Err(trc::AuthEvent::Failed
                                    .into_err()
                                    .ctx(trc::Key::AccountName, address.to_string())
                                    .reason("Master user account not found for fallback admin authentication"))
                            }
                        } else {
                            trc::event!(
                                Auth(trc::AuthEvent::Success),
                                AccountName = fallback_user.to_string(),
                                SpanId = req.session_id,
                            );

                            // inbuxa: AU-1.5, AU-5
                            Ok(AccessToken::new_admin().with_origin(Via::Recovery))
                        }
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, fallback_user.to_string())
                            .ctx(trc::Key::SpanId, req.session_id)
                            .reason("Fallback admin authentication failed"))
                    };
                }

                // Add domain if missing, use the default domain
                self.add_missing_domain(&mut username.account);
                if let Some(master_user) = &mut username.master_user {
                    self.add_missing_domain(master_user);
                }

                // Obtain domain
                let auth_as = username.auth_as();
                let auth_as_address = auth_as.address();
                let auth_as_local = auth_as.local();
                let auth_as_domain = auth_as.domain().unwrap();
                let domain = self.resolve_domain(auth_as_domain).await?;

                // Authenticate app passwords
                if let Some(app_pass) = AppPassword::parse(secret) {
                    if username.is_master() {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, auth_as_address.to_string())
                            .ctx(trc::Key::SpanId, req.session_id)
                            .reason("App passwords cannot be used for impersonation"));
                    }
                    return if let Some(account_id) =
                        self.account_id_from_parts(auth_as_local, domain.id).await?
                    {
                        self.validate_credential(
                            account_id,
                            app_pass.credential_id,
                            app_pass.secret.as_ref(),
                            req.remote_ip,
                            req.session_id,
                        )
                        .await
                        // inbuxa: AU-5
                        .map(|token| {
                            token.with_origin(Via::AppPassword {
                                id: app_pass.credential_id,
                            })
                        })
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, auth_as_address.to_string())
                            .reason("App password authentication failed: account not found"))
                    };
                }

                // Obtain external directory, if any
                let mut is_alias_login = false;
                let token = if let Some(directory) = self.get_directory_for_cached_domain(&domain) {
                    let directory_account = if username.is_master() {
                        directory
                            .authenticate(&Credentials::Basic {
                                username: auth_as_address.to_string(),
                                secret: secret.clone(),
                                mfa_token: mfa_token.clone(),
                            })
                            .await?
                    } else {
                        directory.authenticate(&req.credentials).await?
                    };

                    is_alias_login = directory_account.email != auth_as_address;
                    self.build_directory_token(directory, directory_account, req.remote_ip)
                        .await
                } else if let Some(account_id) =
                    self.account_id_from_parts(auth_as_local, domain.id).await?
                {
                    if let Some(account) = self
                        .registry()
                        .object::<structs::Account>(account_id.into())
                        .await?
                        .and_then(|account| account.into_user())
                    {
                        let Some(credential) = account.password_credential() else {
                            return Err(trc::AuthEvent::Failed
                                .into_err()
                                .ctx(trc::Key::AccountName, auth_as_address.to_string())
                                .ctx(trc::Key::AccountId, account_id)
                                .ctx(trc::Key::SpanId, req.session_id)
                                .reason("Password credential not found for account"));
                        };

                        match verify_mfa_secret_hash(
                            credential.otp_auth.as_deref(),
                            mfa_token.as_deref(),
                            credential.secret.as_str(),
                            secret,
                        )
                        .await?
                        {
                            SecretVerificationResult::Valid => {
                                is_alias_login = account.name != auth_as_local;
                                self.access_token(account_id)
                                    .await
                                    .and_then(|token| AccessToken::new(token, req.remote_ip))
                            }
                            SecretVerificationResult::Invalid => Err(trc::AuthEvent::Failed
                                .into_err()
                                .ctx(trc::Key::AccountName, auth_as_address.to_string())
                                .ctx(trc::Key::AccountId, account_id)
                                .ctx(trc::Key::SpanId, req.session_id)
                                .reason("Authentication failed")),
                            SecretVerificationResult::MissingMfaToken => {
                                Err(trc::AuthEvent::MfaRequired
                                    .into_err()
                                    .ctx(trc::Key::AccountName, auth_as_address.to_string())
                                    .ctx(trc::Key::AccountId, account_id)
                                    .ctx(trc::Key::SpanId, req.session_id)
                                    .reason("MFA token required"))
                            }
                        }
                    } else {
                        Err(trc::AuthEvent::Error
                            .into_err()
                            .ctx(trc::Key::AccountName, auth_as_address.to_string())
                            .ctx(trc::Key::AccountId, account_id)
                            .reason("Account not found in registry"))
                    }
                } else {
                    Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, auth_as_address.to_string())
                        .reason("Account not found"))
                }?;

                // Enforce alias login restrictions
                if is_alias_login && !token.has_permission(Permission::AuthenticateWithAlias) {
                    return Err(trc::AuthEvent::Failed
                        .into_err()
                        .ctx(trc::Key::AccountName, auth_as_address.to_string())
                        .ctx(trc::Key::AccountId, token.account_id())
                        .ctx(trc::Key::SpanId, req.session_id)
                        .reason("Authenticated using an email alias but account does not have AuthenticateAlias permission"));
                }

                // Validate master user access
                if username.is_master() {
                    let master_id = token.account_id(); // inbuxa: AU-5
                    token.assert_has_permissions(&[
                        Permission::Impersonate,
                        Permission::Authenticate,
                    ])?;
                    let address = username.account().address();
                    let master_address = auth_as_address;
                    if let Some(account_id) =
                        self.impersonated_account_id(username.account()).await?
                    {
                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountName = address.to_string(),
                            AccountId = account_id,
                            SpanId = req.session_id,
                            Details = master_address.to_string(),
                        );

                        self.access_token(account_id)
                            .await
                            .map(AccessToken::new_maybe_invalid)
                            // inbuxa: AU-1.5, AU-5: the master stays known
                            .map(|impersonated| {
                                impersonated.with_origin(Via::Master {
                                    account_id: Some(master_id),
                                    name: master_address.to_string(),
                                })
                            })
                    } else {
                        Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, address.to_string())
                            .details(master_address.to_string())
                            .reason("Master user account not found"))
                    }
                } else {
                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = auth_as_address.to_string(),
                        AccountId = token.account_id(),
                        SpanId = req.session_id,
                    );

                    // inbuxa: AU-5 (a directory's token already says so)
                    Ok(if token.origin().is_none() {
                        token.with_origin(Via::Password)
                    } else {
                        token
                    })
                }
            }
            Credentials::Bearer { username, token } => {
                // Handle API key authentication
                if let Some(key) = ApiKey::parse(token) {
                    return self
                        .validate_credential(
                            key.account_id,
                            key.credential_id,
                            key.secret.as_ref(),
                            req.remote_ip,
                            req.session_id,
                        )
                        .await
                        // inbuxa: AU-5
                        .map(|token| token.with_origin(Via::ApiKey { id: key.credential_id }));
                }

                #[cfg(feature = "dev_mode")]
                if std::env::var("API_TOKEN_ADMIN").is_ok_and(|admin_token| &admin_token == token) {
                    return Ok(AccessToken::new_admin());
                }

                // Obtain external directory, if any. When no username is supplied
                // (e.g. HTTP bearer auth), peek at the JWT claims to find the
                // user's domain so per-domain OIDC directories are reachable.
                let directory = match username.as_deref().map(UsernameParts::new) {
                    Some(username) => match username.auth_as().domain() {
                        Some(domain_name) => self.get_directory_for_domain(domain_name).await?,
                        None => self.get_directory_for_token(token).await?,
                    },
                    None => self.get_directory_for_token(token).await?,
                };

                // Try external directory authentication first if supported, then fallback to internal OAuth.
                let mut external_error = None;
                if let Some(directory) = directory
                    && directory.has_bearer_token_support()
                {
                    match directory.authenticate(&req.credentials).await {
                        Ok(result) => {
                            // inbuxa: DIR-7: the token must be the named user's, or
                            // the named address an alias it may sign in with
                            let named = username
                                .as_deref()
                                .map(|name| UsernameParts::new(name).auth_as().address().to_lowercase());
                            let is_alias = match &named {
                                Some(named) if !named.eq_ignore_ascii_case(&result.email) => {
                                    if !result
                                        .email_aliases
                                        .iter()
                                        .any(|alias| alias.eq_ignore_ascii_case(named))
                                    {
                                        return Err(trc::AuthEvent::Failed
                                            .into_err()
                                            .ctx(trc::Key::AccountName, named.clone())
                                            .details(result.email.clone())
                                            .reason("The token belongs to a different user"));
                                    }
                                    true
                                }
                                _ => false,
                            };
                            let token = self
                                .build_directory_token(directory, result, req.remote_ip)
                                .await?;
                            if is_alias && !token.has_permission(Permission::AuthenticateWithAlias) {
                                return Err(trc::AuthEvent::Failed
                                    .into_err()
                                    .ctx(trc::Key::AccountId, token.account_id())
                                    .reason("Authenticated using an email alias but account does not have AuthenticateAlias permission"));
                            }
                            // inbuxa: AU-5
                            return Ok(token.with_origin(Via::Directory));
                        }
                        Err(err) => {
                            external_error = Some(err);
                        }
                    }
                }

                // Internal OAuth
                match self
                    .validate_access_token(GrantType::AccessToken.into(), token)
                    .await
                {
                    Ok(token_info) => self
                        .access_token(token_info.account_id)
                        .await
                        .and_then(|token| AccessToken::new(token, req.remote_ip))
                        // inbuxa: AU-5
                        .map(|token| {
                            token.with_origin(Via::OAuth {
                                client: token_info
                                    .claims
                                    .as_deref()
                                    .filter(|claims| !claims.is_empty())
                                    .unwrap_or("unknown")
                                    .chars()
                                    .take(200)
                                    .collect(),
                            })
                        }),
                    Err(err) => {
                        if let Some(external_error) = external_error {
                            Err(external_error)
                        } else {
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    async fn impersonated_account_id(&self, username: &Username) -> trc::Result<Option<u32>> {
        let address = username.address();

        if let Some(account_id) = self.account_id_from_email(address, false).await? {
            return Ok(Some(account_id));
        }

        if let Some(domain) = username.domain()
            && let Some(domain_cache) = self.domain(domain).await?
            && let Some(directory) = self.get_directory_for_cached_domain(&domain_cache)
            && let Recipient::Account(account) = directory.recipient(address).await?
        {
            // inbuxa: DIR-6
            self.assert_directory_serves(directory, &account.email).await?;
            return Ok(Some(Box::pin(self.synchronize_account(account)).await?.id));
        }

        Ok(None)
    }

    async fn validate_credential(
        &self,
        account_id: u32,
        credential_id: u32,
        secret: &[u8],
        remote_ip: IpAddr,
        span_id: u64,
    ) -> trc::Result<AccessToken> {
        if let Some(account) = self
            .registry()
            .object::<structs::Account>(account_id.into())
            .await?
            .and_then(|account| account.into_user())
        {
            // Find credential by credential_id
            let mut authenticated = false;
            for (credential, credential_type) in
                account.credentials.iter().filter_map(|credential| {
                    credential
                        .as_secondary_credential()
                        .map(|secondary_credential| (secondary_credential, credential))
                })
            {
                if credential.credential_id.document_id() == credential_id {
                    if !verify_secret_hash(&credential.secret, secret).await? {
                        return Err(trc::AuthEvent::Failed
                            .into_err()
                            .ctx(trc::Key::AccountName, account.name)
                            .ctx(trc::Key::AccountId, account_id)
                            .ctx(trc::Key::Id, credential_id)
                            .ctx(trc::Key::SpanId, span_id)
                            .reason("Invalid credential secret"));
                    }

                    if credential
                        .expires_at
                        .as_ref()
                        .is_some_and(|exp| exp.timestamp() < now() as i64)
                    {
                        return Err(trc::AuthEvent::CredentialExpired
                            .into_err()
                            .ctx(trc::Key::AccountName, account.name)
                            .ctx(trc::Key::AccountId, account_id)
                            .ctx(trc::Key::Id, credential_id)
                            .ctx(trc::Key::SpanId, span_id)
                            .reason("Credential has expired"));
                    }

                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = account.name.clone(),
                        AccountId = account_id,
                        Id = credential_id,
                        SpanId = span_id,
                        Details = match credential_type {
                            Credential::AppPassword(_) => "Authenticated with app password",
                            Credential::ApiKey(_) => "Authenticated with API key",
                            _ => "Authenticated with credential",
                        }
                    );

                    authenticated = true;
                    break;
                }
            }

            if authenticated {
                let token = self
                    .access_token_from_account(account_id, structs::Account::User(account))
                    .await?;

                AccessToken::new_scoped(token, credential_id, remote_ip)
                    .add_context(|ctx| ctx.span_id(span_id))
            } else {
                Err(trc::AuthEvent::Failed
                    .into_err()
                    .ctx(trc::Key::AccountId, account_id)
                    .ctx(trc::Key::Id, credential_id)
                    .ctx(trc::Key::SpanId, span_id)
                    .reason("Credential not found for account"))
            }
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountId, account_id)
                .ctx(trc::Key::SpanId, span_id)
                .reason("Account not found for credential"))
        }
    }

    async fn resolve_domain(&self, domain_name: &str) -> trc::Result<Arc<DomainCache>> {
        if let Some(domain) = self.domain(domain_name).await? {
            Ok(domain)
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::Details, domain_name.to_string())
                .reason("Domain not found"))
        }
    }

    fn add_missing_domain(&self, address: &mut Username) {
        if address.domain().is_none() {
            trc::event!(
                Auth(trc::AuthEvent::Warning),
                AccountName = address.address().to_string(),
                Reason = "No domain in username",
            );
            address.domain_start = address.name.len() + 1;
            address.name = format!("{}@{}", address.name, self.core.email.default_domain_name);
        }
    }

    async fn build_directory_token(
        &self,
        directory: &Arc<Directory>,
        account: directory::Account,
        remote_ip: IpAddr,
    ) -> trc::Result<AccessToken> {
        // inbuxa: DIR-6
        self.assert_directory_serves(directory, &account.email).await?;
        let account = Box::pin(self.synchronize_account(account)).await?;
        self.access_token_from_account(account.id, account.account)
            .await
            .and_then(|token| AccessToken::new(token, remote_ip))
    }

    /// inbuxa: DIR-1, DIR-5: the directory a domain signs in against: its
    /// own, else the server default, else the internal one (`None`). An
    /// unknown domain gets the server default.
    pub async fn get_directory_for_domain(
        &self,
        domain_name: &str,
    ) -> trc::Result<Option<&Arc<Directory>>> {
        Ok(match self.domain(domain_name).await? {
            Some(domain) => self.get_directory_for_cached_domain(&domain),
            None => self.get_default_directory(),
        })
    }

    async fn get_directory_for_token(&self, token: &str) -> trc::Result<Option<&Arc<Directory>>> {
        let Some(payload) = JwtClaims::decode_payload(token) else {
            return Ok(self.get_default_directory());
        };
        let Some(claims) = JwtClaims::parse(&payload) else {
            return Ok(self.get_default_directory());
        };

        match (claims.domain(), claims.iss.as_deref()) {
            (Some(domain_name), _) => self.get_directory_for_domain(domain_name).await,
            (None, Some(issuer)) => Ok(self
                .get_directory_for_issuer(issuer)
                .or_else(|| self.get_default_directory())),
            (None, None) => Ok(self.get_default_directory()),
        }
    }

    /// inbuxa: DIR-2: a token naming no address gets the server default, so
    /// no directory is chosen by issuer.
    fn get_directory_for_issuer(&self, _issuer: &str) -> Option<&Arc<Directory>> {
        None
    }

    /// inbuxa: DIR-1, DIR-5: as above, for a domain already read. A
    /// `directoryId` naming no directory the server built is unavailable,
    /// never the internal directory.
    pub fn get_directory_for_cached_domain(&self, domain: &DomainCache) -> Option<&Arc<Directory>> {
        match domain.id_directory {
            Some(directory_id) => Some(
                self.core
                    .storage
                    .directories
                    .get(&directory_id)
                    .unwrap_or_else(|| {
                        trc::event!(
                            Auth(trc::AuthEvent::Warning),
                            Domain = domain.name().to_string(),
                            Id = directory_id,
                            Reason = "The domain's directory doesn't exist; sign-in fails",
                        );
                        unavailable_directory()
                    }),
            ),
            None => self.get_default_directory(),
        }
    }

    /// inbuxa: DIR-6: a directory speaks only for the domains it serves.
    pub async fn assert_directory_serves(
        &self,
        directory: &Arc<Directory>,
        address: &str,
    ) -> trc::Result<()> {
        let serves = match address.rsplit_once('@') {
            Some((_, domain)) => self
                .get_directory_for_domain(domain)
                .await?
                .is_some_and(|effective| Arc::ptr_eq(effective, directory)),
            None => false,
        };
        if serves {
            Ok(())
        } else {
            Err(trc::AuthEvent::Failed
                .into_err()
                .ctx(trc::Key::AccountName, address.to_string())
                .reason("The directory returned an account on a domain it doesn't serve"))
        }
    }
}

/// inbuxa: DIR-5: what a dangling `directoryId` resolves to.
pub fn unavailable_directory() -> &'static Arc<Directory> {
    static UNAVAILABLE: std::sync::OnceLock<Arc<Directory>> = std::sync::OnceLock::new();
    UNAVAILABLE.get_or_init(|| {
        Arc::new(Directory::Unavailable(directory::UnavailableDirectory::new(
            registry::schema::enums::DirectoryType::Ldap,
            "The directory named by the domain doesn't exist",
        )))
    })
}

#[derive(Deserialize)]
struct JwtClaims<'x> {
    #[serde(borrow, default)]
    iss: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    email: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    preferred_username: Option<Cow<'x, str>>,
    #[serde(borrow, default)]
    upn: Option<Cow<'x, str>>,
}

impl<'x> JwtClaims<'x> {
    fn decode_payload(token: &str) -> Option<Vec<u8>> {
        if token.starts_with(TOKEN_HEADER) {
            return None;
        }

        let mut parts = token.split('.');
        let _header = parts.next()?;
        let payload = parts.next()?;
        let _signature = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()
    }

    fn parse(payload: &'x [u8]) -> Option<Self> {
        serde_json::from_slice(payload).ok()
    }

    fn domain(&self) -> Option<&str> {
        [&self.email, &self.preferred_username, &self.upn]
            .into_iter()
            .flatten()
            .find_map(|claim| {
                claim
                    .rsplit_once('@')
                    .map(|(_, domain)| domain)
                    .filter(|domain| !domain.is_empty())
            })
    }
}

impl UsernameParts {
    pub fn new(address: &str) -> Self {
        let mut account = Username {
            name: String::with_capacity(address.len()),
            domain_start: usize::MAX,
        };
        let mut master_user = None;

        for ch in address.chars() {
            if ch == '%' {
                master_user = Some(Username {
                    name: String::with_capacity(address.len()),
                    domain_start: usize::MAX,
                });
            } else {
                let target = master_user.as_mut().unwrap_or(&mut account);
                if ch != '@' {
                    for lower in ch.to_lowercase() {
                        target.name.push(lower);
                    }
                } else {
                    target.name.push(ch);
                    target.domain_start = target.name.len();
                }
            }
        }

        UsernameParts {
            master_user: master_user.filter(|u| u != &account),
            account,
        }
    }

    pub fn auth_as(&self) -> &Username {
        self.master_user.as_ref().unwrap_or(&self.account)
    }

    pub fn account(&self) -> &Username {
        &self.account
    }

    pub fn is_master(&self) -> bool {
        self.master_user.is_some()
    }
}

impl Username {
    pub fn address(&self) -> &str {
        self.name.as_str()
    }

    pub fn local(&self) -> &str {
        self.name
            .get(..self.domain_start.saturating_sub(1))
            .unwrap_or_default()
    }

    pub fn domain(&self) -> Option<&str> {
        self.name.get(self.domain_start..)
    }
}

impl AuthRequest {
    pub fn from_credentials(credentials: Credentials, session_id: u64, remote_ip: IpAddr) -> Self {
        Self {
            credentials,
            session_id,
            remote_ip,
        }
    }

    pub fn from_plain(
        user: impl Into<String>,
        pass: impl Into<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self::from_credentials(
            Credentials::Basic {
                username: user.into(),
                secret: pass.into(),
                mfa_token: None,
            },
            session_id,
            remote_ip,
        )
    }

    pub fn username(&self) -> Option<&str> {
        match &self.credentials {
            Credentials::Basic { username, .. } => Some(username.as_str()),
            Credentials::Bearer { username, .. } => username.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        format!(
            "eyJhbGciOiJSUzI1NiJ9.{}.c2lnbmF0dXJl",
            general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    fn hints(token: &str) -> Option<(Option<String>, Option<String>)> {
        let payload = JwtClaims::decode_payload(token)?;
        let claims = JwtClaims::parse(&payload)?;

        Some((
            claims.domain().map(str::to_string),
            claims.iss.as_deref().map(str::to_string),
        ))
    }

    #[test]
    fn jwt_claims_are_extracted() {
        for (payload, domain, issuer) in [
            (
                r#"{"iss":"https://idp.example.org","email":"John@Example.ORG"}"#,
                Some("Example.ORG"),
                Some("https://idp.example.org"),
            ),
            (
                r#"{"preferred_username":"jane@example.net","upn":"jane@example.com"}"#,
                Some("example.net"),
                None,
            ),
            (
                r#"{"email":"broken@","upn":"jane@example.com"}"#,
                Some("example.com"),
                None,
            ),
            (
                r#"{"iss":"https://idp.example.org","sub":"5db2d1b6","aud":["a","b"],"scope":"openid"}"#,
                None,
                Some("https://idp.example.org"),
            ),
            (r#"{"sub":"5db2d1b6"}"#, None, None),
            (r#"{"email":"jane@example.net"}"#, Some("example.net"), None),
        ] {
            assert_eq!(
                hints(&jwt(payload)),
                Some((domain.map(str::to_string), issuer.map(str::to_string))),
                "Unexpected claims for {payload}"
            );
        }
    }

    #[test]
    fn non_jwt_tokens_are_ignored() {
        for token in [
            "sw1.eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLm9yZyJ9",
            "sw1.eyJhbGciOiJSUzI1NiJ9",
            "opaque-token",
            "one.two",
            "one.two.three.four",
            "",
        ] {
            assert!(
                JwtClaims::decode_payload(token).is_none(),
                "Token {token:?} was parsed as a JWT"
            );
        }
    }
}
