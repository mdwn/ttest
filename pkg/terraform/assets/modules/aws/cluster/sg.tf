resource "aws_security_group" "teleport_sg" {
  name        = "${local.cluster_name_without_dots}-teleport-sg"
  description = "allow inbound TLS, SSH, Teleport traffic"
  vpc_id      = data.aws_vpc.vpc.id

  ingress {
    description = "TLS traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${local.my_ip}/32"]
  }

  ingress {
    description = "SSH traffic"
    from_port   = 3023
    to_port     = 3025
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "internal traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    description      = "all"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group_rule" "app" {
  type              = "ingress"
  from_port         = 9000
  to_port           = 9000
  protocol          = "tcp"
  cidr_blocks = ["${aws_instance.teleport_server.public_ip}/32"]
  security_group_id = aws_security_group.teleport_sg.id
}
