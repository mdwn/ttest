# The configured VPC
data "aws_vpc" "vpc" {
  id = var.vpc_id
}

data "aws_subnets" "dev" {
  filter {
    name = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}

# The route 53 zone to use
data "aws_route53_zone" "zone" {
  name = var.route53_domain
}

# The current IP
data "http" "myip" {
  url = "http://ipv4.icanhazip.com"
}