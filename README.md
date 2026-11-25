# aliyun-tools

Small Aliyun CDN operations CLI.

## Credentials

Set the official Alibaba Cloud SDK environment variables:

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=...
```

## CDN refresh

```bash
aliyun-tools cdn refresh \
  --urls "https://model-dev.aiyou178.com/" \
  --type Directory
```

## CDN HTTPS certificates

Query the certificate currently bound to an accelerated domain:

```bash
aliyun-tools cdn cert query --domain "$CDN_EDGE_DOMAIN"
```

Upload a PEM certificate chain and its private key to that domain:

```bash
aliyun-tools cdn cert update \
  --domain "$CDN_EDGE_DOMAIN" \
  --cert-file certificate.pem \
  --key-file private.key
```

Check the certificate's validity, domain coverage and key match before updating.
For example, inspect the certificate with
`openssl x509 -in certificate.pem -noout -dates -subject -fingerprint -sha256`.

The update command changes the live certificate directly. `edgescript test-staging`
tests routes, not a pending HTTPS certificate change.

`--name` optionally names the uploaded certificate. Updating enables HTTPS and
applies directly to the specified CDN domain; it does not use EdgeScript staging
or publish frontend assets. Use the accelerated domain name registered in CDN,
including its wildcard notation if applicable, and update each binding separately.
The certificate and key are sent in a signed POST body, not in the URL.

The credential needs `cdn:DescribeDomainCertificateInfo` for queries and
`cdn:SetCdnDomainSSLCertificate` for updates. Query again after updating to check
the certificate status and expiration, then verify the certificate served over
HTTPS after propagation.

## EdgeScript operations

```bash
aliyun-tools edgescript query --domain "$CDN_EDGE_DOMAIN" --env production
aliyun-tools edgescript sync-production-to-staging --domain "$CDN_EDGE_DOMAIN"
aliyun-tools edgescript push-staging \
  --domain "$CDN_EDGE_DOMAIN" \
  --rule-file cdn/edgescript.generated.es \
  --name static_site_rewrite \
  --pri 1 \
  --pos head \
  --mode upsert
aliyun-tools edgescript publish-staging --domain "$CDN_EDGE_DOMAIN"
aliyun-tools edgescript rollback-staging --domain "$CDN_EDGE_DOMAIN"
aliyun-tools edgescript test-staging --url "https://admin2.aiyou178.com/"
```
