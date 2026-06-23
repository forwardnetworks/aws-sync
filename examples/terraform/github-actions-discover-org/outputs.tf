output "role_arn" {
  description = "Role ARN to use with aws-actions/configure-aws-credentials."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "GitHub Actions discovery role name."
  value       = aws_iam_role.this.name
}
