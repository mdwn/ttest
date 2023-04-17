data "aws_caller_identity" "current" {}

locals {
    username = split(":", data.aws_caller_identity.current.user_id)[1]
}

resource "aws_key_pair" "ssh-access" {
    key_name   = "deploy-${local.username}"
    public_key = var.public_key
}