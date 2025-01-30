# secquiry-sso

## Usage

Create a config file. You can use secquirysso.conf.json.sample as a guide.

Replace values with your Cogged server host details and OIDC identity provider and client Oauth2 app parameters

```
export SECQUIRYSSO_CUSER=ssouser SECQUIRYSSO_CPASS=xxxxxxxxxxxxxx
./secquiry-sso -p 8901 -conf /path/to/secquirysso.conf.json
```
