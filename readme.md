# caddy-ldapauthz

Caddy handler that authorizes an already-authenticated user by Active Directory group membership. OIDC authentication can be handled by [caddy-security](https://github.com/greenpau/caddy-security); this module runs after it, looks the user up in AD, and enforces group access.

## Build

```sh
go mod tidy
xcaddy build \
  --with github.com/greenpau/caddy-security \
  --with github.com/haught/caddy-ldapauthz=./
```

## Options

| Option | Default | Description |
|---|---|---|
| `url` | required | `ldaps://host:636`, or `ldap://host:389` with `starttls` |
| `base_dn` | required | Search base for users and groups |
| `bind_dn` / `bind_password` | required | Service account. Password supports `{env.VAR}` |
| `user` | `{http.auth.user.email}` | Placeholder holding the authenticated identity |
| `user_filter` | UPN match, enabled user accounts only | Must contain `{user}` (escaped before use) |
| `strip_domain` | off | Drop `@domain` from the identity before lookup |
| `nested` | off | Resolve nested groups (`LDAP_MATCHING_RULE_IN_CHAIN`) |
| `starttls` | off | Upgrade `ldap://` with StartTLS |
| `ca_file` | system pool | PEM CA bundle for the DC certificate |
| `allow` | | Full group DNs (compared case-insensitively). Repeatable. Empty allows any found user |
| `cache_ttl` | `5m` | Lifetime of successful lookups. Not-found results are never cached |
| `timeout` | `5s` | Dial and query timeout |
| `stale_ttl` | `1h` | Keep using a cached result this long past `cache_ttl` if the directory is unreachable; `off` disables |

Responses: `401` no identity, `403` user not found or not in an allowed group, `503` directory error.

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
			base_dn "DC=corp,DC=example,DC=com"
			bind_dn "CN=svc-caddy,OU=Service Accounts,DC=corp,DC=example,DC=com"
			bind_password {env.LDAP_BIND_PASSWORD}
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
strip_domain
user_filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName={user}))"
```
