# The server: one ECS service on Fargate (Graviton), in the private subnets,
# reachable only from the load balancer.

resource "aws_cloudwatch_log_group" "server" {
  name              = "/engramport/${var.environment}/server"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.stack.arn
}

resource "aws_ecs_cluster" "main" {
  # checkov:skip=CKV_AWS_65:Container Insights costs extra; the load balancer's health and 5xx alarms cover the pilot. Turn on with more tasks.
  name = local.name
  setting {
    name  = "containerInsights"
    value = "disabled" # extra cost; the load balancer's metrics and alarms cover the pilot
  }
}

locals {
  plain_env = {
    ENGRAMPORT_MODE                     = "http"
    ENGRAMPORT_PORT                     = "8080"
    ENGRAMPORT_STORE                    = "postgres"
    ENGRAMPORT_DATABASE_CA_FILE         = "/app/certs/supabase-ca.crt"
    ENGRAMPORT_EMBED_URL                = var.embed_url
    ENGRAMPORT_OAUTH                    = "true"
    ENGRAMPORT_PUBLIC_URL               = var.public_url
    ENGRAMPORT_SUPABASE_URL             = var.supabase_url
    ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY = var.supabase_publishable_key
    ENGRAMPORT_OAUTH_REDIRECT_HOSTS     = join(",", var.oauth_redirect_hosts)
    ENGRAMPORT_APPROVAL_PAGE            = tostring(var.pages.approval)
    ENGRAMPORT_ERASURE_PAGE             = tostring(var.pages.erasure)
    ENGRAMPORT_EXPORT_PAGE              = tostring(var.pages.export)
    ENGRAMPORT_RESTORE_PAGE             = tostring(var.pages.restore)
    ENGRAMPORT_CELL_ERASURE_PAGE        = tostring(var.pages.cell_erasure)
    ENGRAMPORT_ACCEPT_PAGE              = tostring(var.pages.accept)
    ENGRAMPORT_GRANT_PAGE               = tostring(var.pages.grant)
    NODE_ENV                            = "production"
  }
}

resource "aws_ecs_task_definition" "server" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  # Scratch space at /tmp; everything else in the container is read-only.
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "server"
    image                  = var.image
    essential              = true
    user                   = "1000:1000"
    readonlyRootFilesystem = true
    stopTimeout            = 30
    portMappings           = [{ containerPort = 8080, protocol = "tcp" }]
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [for k, v in local.plain_env : { name = k, value = v }]
    secrets = [for key, s in local.secrets : {
      name      = s.env
      valueFrom = aws_secretsmanager_secret.server[key].arn
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.server.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "server"
      }
    }
  }])
}

resource "aws_ecs_service" "server" {
  name                              = local.name
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.server.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  enable_execute_command            = false
  health_check_grace_period_seconds = 30
  propagate_tags                    = "SERVICE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.server.arn
    container_name   = "server"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.https]
}
