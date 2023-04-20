output "region" {
    value       = data.aws_region.current.name
    description = "The currently configured region."
}