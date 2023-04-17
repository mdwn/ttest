resource "aws_launch_template" "template" {
  name          = "${local.cluster_name_without_dots}-launch-template"
  instance_type = "t2.medium"
  image_id      = var.ami_id
  key_name      = var.key_name
  vpc_security_group_ids = [aws_security_group.teleport_sg.id]
}

resource "aws_instance" "teleport_server" {
  launch_template {
    id      = aws_launch_template.template.id
    version = "$Latest"
  }

  tags = {
    Name = "${local.cluster_name_without_dots}_teleport_host"
  }
}

resource "aws_instance" "teleport_nodes" {
  count = var.node_count
  launch_template {
    id      = aws_launch_template.template.id
    version = "$Latest"
  }

  tags = {
    Name = "${local.cluster_name_without_dots}_teleport_node_${count.index}"
  }
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = local.proxy_fqdn
  ttl     = 60
  type    = "A"
  records = [aws_instance.teleport_server.public_ip]
}

resource "aws_route53_record" "subdomains" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = "*.${local.proxy_fqdn}"
  ttl     = 60
  type    = "A"
  records = [aws_instance.teleport_server.public_ip]
}
