variable "route53_domain" {
  type        = string
  description = "the route 53 domain"
}

variable "vpc_id" {
  type        = string
  description = "the VPC ID to use"
}

variable "ami_id" {
  type        = string
  description = "the AMI to use to provision up Teleport instances"
}

variable "node_count" {
  type        = number
  description = "the number of additional nodes to provision"
  default     = 0
}

variable "key_name" {
  type        = string
  description = "the key name to use to provision the instances"
}

variable "cluster_name" {
  type        = string
  description = "the name of the cluster"
}