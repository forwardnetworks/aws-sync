data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AllowTrustedPrincipals"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }

    dynamic "condition" {
      for_each = var.external_id == null ? [] : [var.external_id]

      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
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
