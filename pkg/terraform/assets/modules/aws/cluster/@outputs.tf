output "server_ip" {
    value       = aws_instance.teleport_server.public_ip
    description = "The Teleport server IP address."
}

output "node_ips" {
    value       = [for node in aws_instance.teleport_nodes: node.public_ip]
    description = "The Teleport node IP addresses."
}

output "proxy_fqdn" {
    value       = local.proxy_fqdn
    description = "The FQDN of the proxy."
}