# The load balancer: TLS 1.2 and 1.3 only, HTTP redirected, HSTS added, the
# Server header removed, idle timeout long enough for MCP streams and exports.

resource "aws_lb" "main" {
  # checkov:skip=CKV_AWS_91:Access logs would record every full URL, including the one-time codes on sign-in callbacks (docs/hosting.md). On only for an investigation.
  # checkov:skip=CKV2_AWS_76:WAF is off for the pilot (var.enable_waf). When on, it carries AWSManagedRulesKnownBadInputsRuleSet, which covers Log4j.
  name                       = local.name
  load_balancer_type         = "application"
  internal                   = !var.public_access
  subnets                    = var.public_access ? aws_subnet.public[*].id : aws_subnet.private[*].id
  security_groups            = [aws_security_group.alb.id]
  idle_timeout               = 300
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "strictest"
  enable_deletion_protection = true
  # Access logs stay off: they would record every full URL, including the
  # one-time codes on sign-in callbacks, which the server never logs.
}

resource "aws_lb_target_group" "server" {
  name                 = local.name
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 60

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  routing_http_response_strict_transport_security_header_value = "max-age=31536000; includeSubDomains"
  routing_http_response_x_content_type_options_header_value    = "nosniff"
  routing_http_response_server_enabled                         = false

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
