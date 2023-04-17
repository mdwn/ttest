version: v2
teleport:
  nodename: {{.ClusterName}}
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO
    format:
      output: text
  ca_pin: ""
  diag_addr: ""
auth_service:
  {{if .LicenseFile}}license_file: {{.LicenseFile}}{{end}}
  enabled: "yes"
  listen_addr: 0.0.0.0:3025
  cluster_name: {{.ClusterName}}
  proxy_listener_mode: multiplex
ssh_service:
  enabled: "yes"
  commands:
  - name: hostname
    command: [hostname]
    period: 1m0s
proxy_service:
  enabled: "yes"
  web_listen_addr: 0.0.0.0:443
  public_addr: {{.ProxyFQDN}}:443
  acme:
    enabled: yes
    email: {{.LetsEncryptEmail}}
    uri: {{.LetsEncryptURI}}