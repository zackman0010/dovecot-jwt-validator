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

Create a config file `jwks.conf` in the same directory as the combined binary. The location and name of this file can be configured
with the `--config` CLI flag.
This config file contains three key=value pairs:
- `oidc_url`: OIDC configuration URL, provided by your auth server
- `socket_path`: Path to the Unix socket that will be used for communication between Dovecot and the application
- `client_id`: Optional field for the oAuth Client ID that generated the JWT. If present, the `azp` field on the JWT must match

On launch, the application will generate a Dovecot configuration file containing the oAuth2 parameters. By default, the file will
be created at `/etc/dovecot/dovecot-oauth2.conf.ext`. The output path can be configured with the `--output` CLI flag. The main
Dovecot config file will need to be configured to import this generated config file:
```
passdb {
  driver = oauth2
  mechanisms = xoauth2 oauthbearer
  args = /etc/dovecot/dovecot-oauth2.conf.ext
}
```

This repo also contains a systemd service file that can be used to set the application up as a service. It will autostart on server
launch and set itself as a dependency of Dovecot, so that Dovecot cannot launch without it.

The application is expected to run as the same user as Dovecot, by default `dovecot`.

## Reference URLs

- [Dict Protocol](https://doc.dovecot.org/2.4.2/developers/design/dict_protocol.html)
- [Local Validation](https://doc.dovecot.org/2.4.2/core/config/auth/databases/oauth2.html#local-validation)

## AI Disclosure

I utilized Claude Code to help me develop this application. I am a Kotlin developer by trade and am not familiar enough with Go to
confidently develop in it. I wanted this app to be as lightweight as possible and to run without any external dependencies. As a
JVM language, Kotlin is the opposite of both of those goals.
