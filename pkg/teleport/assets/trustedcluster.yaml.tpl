kind: trusted_cluster
version: v2
metadata:
  name: {{.RootClusterName}}
spec:
  enabled: true
  token: {{.TrustedClusterToken}}
  tunnel_addr: {{.RootProxyFQDN}}:443
  web_proxy_addr: {{.RootProxyFQDN}}:443
  role_map:
    - remote: "access"
      local: ["visitor"]