data "aws_caller_identity" "current" {}

data "aws_route53_zone" "domain" {
  name         = var.domain
  private_zone = false
}

data "archive_file" "lambda_function_poc_demo" {
  type = "zip"

  source_dir = "${path.module}/lambdas/poc_demo"
  output_path = "${path.module}/poc_demo.zip"  
}
