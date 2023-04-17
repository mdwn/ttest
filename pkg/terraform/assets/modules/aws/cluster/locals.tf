locals {
  proxy_fqdn = "${var.cluster_name}.${var.route53_domain}"
  cluster_name_without_dots = replace(var.cluster_name, ".", "-")
  my_ip = chomp(data.http.myip.response_body)
}
