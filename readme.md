# caddy-ldapauthz

Caddy handler that authorizes an already-authenticated user by Active Directory group membership. OIDC authentication can be handled by [caddy-security](https://github.com/greenpau/caddy-security); this module runs after it, looks the user up in AD, and lets the request through only if AD confirms the user is in an allowed group.

## Build

```sh
go mod tidy
xcaddy build \
  --with github.com/greenpau/caddy-security \
  --with github.com/haught/caddy-ldapauthz=./
```

## Testing

`go test -race ./...` runs the unit tests and drives the real directory lookup against a fake LDAP server, over both LDAPS and StartTLS.

[test/](test/) builds Caddy with caddy-security and this checkout, and runs a site that logs in with OIDC and then applies `ldap_authz`:

```sh
cd test
make run   # first run creates .env from .env.example; fill it in and re-run
```

Register `<SITE_ORIGIN>/_authcrunch/oauth2/ldapauthz/authorization-code-callback` as the redirect URI with your IdP. `make validate` checks the config, and `make adapt` prints the JSON it adapts to.

## Options

| Option | Default | Description |
|---|---|---|
| `url` | required | `ldaps://host[:636]`, or `ldap://host[:389]` with `starttls`. Scheme, host and port only |
| `base_dn` | required | Search base for users |
| `bind_dn` / `bind_password` | required | Service account. Set the password with `{env.VAR}` or `{file./path}` |
| `user` | `{http.auth.user.email}` | Placeholder holding the authenticated identity |
| `user_filter` | UPN match on enabled, unexpired accounts | Must contain `{user}`, which is escaped before use. `{now_filetime}` is the current time, for `accountExpires` |
| `strip_domain <domain...>` | | Accept only identities ending in `@<domain>`, and drop that suffix before lookup. Repeatable |
| `require <placeholder> <value...>` | | Deny unless the placeholder holds one of the values, e.g. `require {http.auth.user.realm} corp`. Repeatable |
| `nested [on\|off]` | off | Count nested group membership (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `starttls [on\|off]` | off | Upgrade `ldap://` with StartTLS |
| `ca_file` | system pool | PEM CA bundle for the DC certificate |
| `allow` | required | Full group DNs, resolved and compared by AD. Repeatable |
| `allow_any_user [on\|off]` | off | Permit every user `user_filter` finds. Needed to run without `allow` |
| `cache_ttl` | `5m` | How long the answer for a user found in AD is cached, allowed or not |
| `negative_ttl` | `30s` | How long a user who is not found, or matches more than one entry, is cached as denied |
| `timeout` | `5s` | Most time a request waits for the directory, including queueing, connecting, TLS, bind and searches |
| `stale_ttl` | off | Keep using a cached answer this long past its expiry while the directory is unreachable |

Responses: `401` no identity, `403` denied, `503` directory unreachable. The response never says why; the reason is in Caddy's log.

Every option can be set from an environment variable, e.g. `base_dn "{$LDAP_BASE_DN}"`. An empty or missing value keeps the default, except where that would fail open: an empty `allow` is an error unless `allow_any_user` is on, and `require` with a placeholder but no value is an error. A flag with no value is on, so quote it and give it a default: `nested "{$LDAP_NESTED:off}"`.

## Example

```caddyfile
{
	security {
		oauth identity provider dex {
			realm dex
			driver generic
			client_id {env.OIDC_CLIENT_ID}
			client_secret {env.OIDC_CLIENT_SECRET}
			scopes openid email profile
			base_auth_url https://dex.example.com
			metadata_url https://dex.example.com/.well-known/openid-configuration
		}

		authentication portal portal {
			crypto default token lifetime 3600
			enable identity provider dex
			cookie domain example.com
			transform user {
				match realm dex
				action add role authp/user
			}
		}

		authorization policy users {
			set auth url https://auth.example.com/oauth2/dex
			allow roles authp/user
		}
	}
}

auth.example.com {
	route {
		authenticate with portal
	}
}

app.example.com {
	route {
		authorize with users
		ldap_authz {
			url ldaps://dc.corp.example.com:636
			ca_file /etc/ssl/corp-root-ca.pem
			base_dn "DC=corp,DC=example,DC=com"
			bind_dn "CN=svc-caddy,OU=Service Accounts,DC=corp,DC=example,DC=com"
			bind_password {env.LDAP_BIND_PASSWORD}
			require {http.auth.user.realm} dex
			nested
			allow "CN=App-Admins,OU=Groups,DC=corp,DC=example,DC=com"
			allow "CN=App-Users,OU=Groups,DC=corp,DC=example,DC=com"
		}
		reverse_proxy localhost:8080
	}
}
```

Matching by `sAMAccountName` instead of UPN:

```caddyfile
strip_domain corp.example.com
user_filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName={user})(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(accountExpires=0)(accountExpires>={now_filetime})))"
```

A custom `user_filter` replaces the default entirely, so keep the disabled-account and `accountExpires` clauses.

## Security notes

- **Pin the identity provider.** caddy-security sets `{http.auth.user.realm}` to the realm of the provider that logged the user in. `require {http.auth.user.realm} <realm>` keeps users of any other provider, such as a social login, from being mapped onto AD accounts. Don't pin `{http.auth.user.issuer}`: caddy-security derives it from the login request's `X-Forwarded-Host` header.
- **Map only claims the user cannot edit.** The default maps the `email` claim onto `userPrincipalName`. caddy-security's generic OIDC driver requires an email claim but does not check `email_verified`. Use a single-tenant IdP whose email or username comes from AD or is otherwise set only by administrators. Avoid `preferred_username` unless your IdP guarantees the same.
- **Keep the bind password out of the config.** `{env.VAR}` and `{file./path}` are resolved at startup. `{$VAR}` is substituted when the Caddyfile is adapted, so the password would land in the JSON config, the admin API and `autosave.json`. Use a dedicated, read-only service account.
- **Pin the DC's CA** with `ca_file`, so that only your enterprise CA can vouch for the DC.
- **Use security groups.** Membership of any group named in `allow` grants access, so don't allow distribution lists or groups whose members can add themselves.
- **Revocation is not instant.** A user removed from a group or disabled in AD keeps access until their cached answer expires, up to `cache_ttl`, plus `stale_ttl` during an outage if you enable it. Long-lived connections such as WebSockets are checked once, when they open.
- **Cover every path.** Put `ldap_authz` in the same route as the upstream, with no path matcher in front of it, so every request that reaches the upstream is checked.
