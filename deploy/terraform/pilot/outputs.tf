output "load_balancer_dns_name" {
  description = "Point the EngramPort domain here (an alias or CNAME record)."
  value       = aws_lb.main.dns_name
}

output "load_balancer_internal" {
  description = "True until public access is decided."
  value       = aws_lb.main.internal
}

output "ecr_repository_url" {
  description = "Push the server image here, then pin it by digest in var.image."
  value       = aws_ecr_repository.server.repository_url
}

output "secret_names" {
  description = "The secrets a person sets once, outside Terraform. Names only."
  value       = { for k, s in aws_secretsmanager_secret.server : local.secrets[k].env => s.name }
}

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "service_name" {
  value = aws_ecs_service.server.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.server.name
}

output "nat_public_ip" {
  description = "The one address the tasks' outbound traffic comes from, for Supabase network restrictions."
  value       = aws_eip.nat.public_ip
}
