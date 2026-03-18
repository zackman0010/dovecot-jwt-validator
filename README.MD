# Dovecot JWT Validator

Despite the name, this does not actually perform the JWT validation. That is performed by Dovecot itself. However, in order to validate
a JWT, Dovecot has to have access to the auth server's public key. Normally, OIDC compliant clients will use the OIDC config to look up
the public key using the JWKS URL. However, Dovecot does not do this. It instead expects the public key to be available via a `dict`.

This application implements the Dovecot Dict Protocol, allowing it to be used as a Dict Proxy. When Dovecot performs the LOOKUP for the
public key, this application will use the OIDC config to get the JWKS URL, pull the public key from the JWKS, format it as Dovecot
expects, then return the key back to Dovecot for use in validating the JWT. Doing so allows Dovecot to validate oAuth2 clients without
having to copy the public key to the Dovecot server each time it changes or giving Dovecot its own client/secret to authenticate to
the token introspection endpoint.

## Running the application

### Config file

Create a config file at `/etc/dovecot-jwks/jwks.conf`. It contains three key=value pairs:
- `oidc_url`: OIDC configuration URL, provided by your auth server
- `socket_path`: Path (or filename) for the Unix socket used for communication between Dovecot and the application
- `client_id`: Optional field for the oAuth Client ID that generated the JWT. If present, the `azp` field on the JWT must match

### Path resolution

The `--config`, `--output`, and `socket_path` values follow the same rule: if the value starts with `/` it is used as-is; otherwise
it is treated as a filename relative to a directory controlled by an environment variable:

| Flag / config key | Environment variable      | Default directory (systemd) |
|-------------------|---------------------------|-----------------------------|
| `--config`        | `CONFIGURATION_DIRECTORY` | `/etc/dovecot-jwks`         |
| `--output`        | `STATE_DIRECTORY`         | `/var/lib/dovecot-jwks`     |
| `socket_path`     | `RUNTIME_DIRECTORY`       | `/run/dovecot-jwks`         |

If the environment variable is not set, the path is resolved relative to the working directory.

### systemd service

This repo includes a systemd service file. It sets `ConfigurationDirectory`, `StateDirectory`, and `RuntimeDirectory` to
`dovecot-jwks`, so systemd creates and manages the directories listed above and exports the environment variables automatically.
No CLI flags are needed when running under systemd. The service autostarts with the server and declares itself a dependency of
Dovecot, so Dovecot cannot launch without it.

Install and enable:
```
sudo cp dovecot-jwks.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dovecot-jwks
```

The application runs as the `dovecot` user so the Unix socket is accessible to Dovecot.

### Dovecot configuration

On launch, the application writes a Dovecot OAuth2 config file to the output path (default
`/var/lib/dovecot-jwks/dovecot-oauth2.conf.ext`). The main Dovecot config must import it:
```
passdb {
  driver = oauth2
  mechanisms = xoauth2 oauthbearer
  args = /var/lib/dovecot-jwks/dovecot-oauth2.conf.ext
}
```

## Reference URLs

- [Dict Protocol](https://doc.dovecot.org/2.4.2/developers/design/dict_protocol.html)
- [Local Validation](https://doc.dovecot.org/2.4.2/core/config/auth/databases/oauth2.html#local-validation)

## AI Disclosure

I utilized Claude Code to help me develop this application. I am a Kotlin developer by trade and am not familiar enough with Go to
confidently develop in it. I wanted this app to be as lightweight as possible and to run without any external dependencies. As a
JVM language, Kotlin is the opposite of both of those goals.
