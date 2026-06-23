locals {
  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : coalesce(var.github_oidc_provider_arn, "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com")
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.github_oidc_thumbprint_list

  tags = var.tags
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AllowGitHubActions"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.github_subject_patterns
    }
  }
}

data "aws_iam_policy_document" "organizations_read" {
  statement {
    sid = "ReadOrganizationsAccounts"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
      "organizations:ListParents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "this" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
  tags               = var.tags

  lifecycle {
    precondition {
      condition     = var.create_github_oidc_provider || var.github_oidc_provider_arn != null
      error_message = "github_oidc_provider_arn is required when create_github_oidc_provider is false."
    }
  }
}

resource "aws_iam_policy" "organizations_read" {
  name        = "${var.role_name}-organizations-read"
  description = "Read-only AWS Organizations permissions for awssync discover-org."
  policy      = data.aws_iam_policy_document.organizations_read.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "organizations_read" {
  role       = aws_iam_role.this.name
  policy_arn = aws_iam_policy.organizations_read.arn
}
