provider "aws" {
  region = "us-west-2"
}

# Define the OIDC Providers for Conductor
resource "aws_cognito_identity_provider" "conductor_oidc" {
  provider_name             = "conductor-oidc-provider"
  provider_type             = "OIDC"
  provider_details          = {
    "client_id"             = "your-oidc-client-id"
    "client_secret"         = "your-oidc-client-secret"
    "metadata_url"          = "https://your-oidc-metadata-url"
    "authorize_scopes"      = "openid profile email"
  }
  attribute_mapping {
    email      = "email"
    username   = "sub"
    first_name = "given_name"
    last_name  = "family_name"
  }
  provider_tags = {
    service = "Conductor"
  }
}

# Define the Trust Relationship Policy
data "aws_iam_policy_document" "trust_relationship" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [aws_cognito_identity_provider.conductor_oidc.client_id]
    }

    principals {
      type        = "Federated"
      identifiers = [aws_cognito_identity_provider.conductor_oidc.arn]
    }
  }
}

# Create the IAM Role for Conductor Access
resource "aws_iam_role" "conductor_access_role" {
  name               = "ConductorAccessRole"
  assume_role_policy = data.aws_iam_policy_document.trust_relationship.json
}

# Attach Permissions Policies to the Role (Add your policies here)
resource "aws_iam_policy_attachment" "conductor_access_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  roles      = [aws_iam_role.conductor_access_role.name]
}
