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

## EdgeScript operations

```bash
aliyun-tools edgescript query --domain "$CDN_EDGE_DOMAIN" --env production
aliyun-tools edgescript push-staging \
  --domain "$CDN_EDGE_DOMAIN" \
  --rule-file cdn/edgescript.generated.es \
  --name static_site_rewrite \
  --pri 1 \
  --pos head
aliyun-tools edgescript publish-staging --domain "$CDN_EDGE_DOMAIN"
aliyun-tools edgescript rollback-staging --domain "$CDN_EDGE_DOMAIN"
```
