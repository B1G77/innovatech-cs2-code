# A new cloud application ("inventory API") the office uses over the VPN:
# internal load balancer + self-healing group of two servers in two AZs.

# EC2 trust policy, shared by the app servers and the ops host.
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${var.project}-app-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "app" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ])

  role       = aws_iam_role.app.name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "app_bundle" {
  name = "${var.project}-app-bundle"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app-profile"
  role = aws_iam_role.app.name
}

resource "aws_security_group" "alb" {
  name        = "${var.project}-app-alb"
  description = "Internal load balancer: HTTP from private ranges"
  vpc_id      = aws_vpc.this["workload"].id

  ingress {
    description = "Office and hub"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = [local.onprem_cidr, local.vpcs.shared]
  }

  egress {
    protocol    = "tcp"
    from_port   = 8080
    to_port     = 8080
    cidr_blocks = [local.vpcs.workload]
  }

  tags = { Name = "${var.project}-app-alb" }
}

resource "aws_security_group" "app" {
  name        = "${var.project}-app"
  description = "App servers: only the load balancer may call them"
  vpc_id      = aws_vpc.this["workload"].id

  ingress {
    description     = "From the load balancer"
    protocol        = "tcp"
    from_port       = 8080
    to_port         = 8080
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-app" }
}

# What the SOAR swaps in when it isolates a cloud host: nothing in, only HTTPS out so the
# host stays manageable through SSM (the same idea as EDR "isolation with management").
# In AWS VPCs the Route 53 resolver is not filtered by security groups, so DNS keeps working.
resource "aws_security_group" "quarantine" {
  for_each = toset(["workload"])

  name        = "${var.project}-${each.key}-quarantine"
  description = "SOAR isolation: no inbound, management channel only"
  vpc_id      = aws_vpc.this[each.key].id

  egress {
    description = "SSM management channel and SOAR webhook"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-${each.key}-quarantine" }
}

resource "aws_lb" "app" {
  name               = "${var.project}-app"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.this["workload-app-a"].id, aws_subnet.this["workload-app-b"].id]
}

resource "aws_lb_target_group" "app" {
  name                 = "${var.project}-app"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = aws_vpc.this["workload"].id
  deregistration_delay = 30

  health_check {
    path                = "/health"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "app" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_launch_template" "app" {
  name_prefix = "${var.project}-app-"
  image_id    = data.aws_ssm_parameter.al2023.value
  # t3.small, not t3.micro: on 1 GB a new server running its first Ansible upgrade and a patch scan
  # at the same time froze at 100% CPU and was replaced by Auto Scaling (found in testing, 28 Oct).
  instance_type = "t3.small"
  user_data     = filebase64("${path.module}/files/app_user_data.sh")

  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  metadata_options {
    http_tokens = "required"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 8
      encrypted   = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${var.project}-app"
      Role       = "app"
      PatchGroup = var.project
    }
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${var.project}-app"
  min_size                  = 2
  max_size                  = 4
  desired_capacity          = 2
  vpc_zone_identifier       = [aws_subnet.this["workload-app-a"].id, aws_subnet.this["workload-app-b"].id]
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  # The app needs the hub NAT for its first package installs.
  depends_on = [aws_ec2_transit_gateway_route.workload_default, aws_nat_gateway.shared]
}
