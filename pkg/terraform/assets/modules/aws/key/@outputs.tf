output "key_name" {
    value       = aws_key_pair.ssh-access.key_name
    description = "The key name created."
}