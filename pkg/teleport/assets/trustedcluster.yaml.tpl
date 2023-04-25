kind: trusted_cluster
version: v2
metadata:
  name: {{.RootClusterName}}
spec:
  enabled: true
  token: {{.TrustedClusterToken}}
  tunnel_addr: {{.ProxyFQDN}}
  web_proxy_addr: {{.ProxyFQDN}}
  role_map:
    - remote: "access"
      local: ["visitor"]