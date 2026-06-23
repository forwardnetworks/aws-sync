variable "role_name" {
  description = "IAM role name for GitHub Actions awssync discover-org runs."
  type        = string
  default     = "awssync-github-discover-org"
}

variable "create_github_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider if it does not already exist."
  type        = bool
  default     = false
}

variable "github_oidc_provider_arn" {
  description = "Existing GitHub Actions OIDC provider ARN. Required when create_github_oidc_provider is false."
  type        = string
  default     = null
}

variable "github_oidc_thumbprint_list" {
  description = "Thumbprints used if this example creates the GitHub Actions OIDC provider."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

variable "github_subject_patterns" {
  description = "Allowed GitHub OIDC subject patterns, for example repo:ORG/REPO:ref:refs/heads/main."
  type        = list(string)

  validation {
    condition     = length(var.github_subject_patterns) > 0
    error_message = "github_subject_patterns must contain at least one subject pattern."
  }
}

variable "tags" {
  description = "Tags added to created IAM resources."
  type        = map(string)
  default     = {}
}
