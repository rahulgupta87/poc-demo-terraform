resource "aws_iam_policy" "lambda_poc_demo_policy" {
          
    name   = "poc-demo-lambdaBasicExecutionRole-${var.env_type}"
    path   = "/service-role/"

    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [
        {
          Sid      = "CreateLogGroupPermissions"
          Effect   = "Allow"
          Action   = "logs:CreateLogGroup",
          Resource = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:*"
        },
        {
          Sid = "CreateLogStreamAndPutLogEventsPermissions"
          Effect = "Allow"
          Action = [
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/poc-demo-${var.env_type}:*"
        }
      ]
    })
}

resource "aws_iam_policy" "lambda_poc_demo_policy" {
          
    name   = "poc-demo-inlinePolicy-${var.env_type}"
    path   = "/service-role/"

    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [
        {
          Sid    = "NetworkingPermissions"
          Effect = "Allow"
          Action = [
            "ec2:CreateNetworkInterface",
            "ec2:DeleteNetworkInterfacePermission",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DeleteNetworkInterface",
            "ec2:AttachNetworkInterface"
          ]
          Resource = "*"
        },
        {
          Sid    = "SSMPermissions"
          Effect = "Allow"
          Action = [
            "ssm:PutParameter",
            "ssm:GetParameter"
          ]
          Resource = "*"
        },
        {
          Sid      = "DatabasePermissions"
          Effect   = "Allow"
          Action   = [
            "dynamodb:PutItem",
            "dynamodb:Scan",
            "dynamodb:GetItem"
          ]
          Resource = aws_dynamodb_table.dynamodb_table.arn
        },
        {
          Sid      = "SecretManagerPermissions"
          Effect   = "Allow"
          Action   = "secretsmanager:GetSecretValue"
          Resource =  "arn:aws:secretsmanager:us-east-1:${data.aws_caller_identity.current.account_id}:secret:/${var.env_type}/poc-demo/*"
  
        }

      ]
    })

    depends_on = [
      aws_ssm_parameter.ssm_max_id,
      aws_ssm_parameter.ssm_thirdparty,
      aws_dynamodb_table.dynamodb_table
    ] 
}

resource "aws_lambda_function" "lambda_function_poc_demo" {
          
    description   = ""
    function_name = "poc-demo-${var.env_type}"
    handler       = "lambda_function.lambda_handler"
    architectures = [
        "x86_64"
    ]
    filename    = "${path.module}/poc-demo.zip"
    memory_size = 128
    role        = "${aws_iam_role.lambda_role_poc_demo.arn}"
    runtime     = "python3.7"
    timeout     = 600

    tracing_config {
        mode = "PassThrough"
    }

    vpc_config {
        subnet_ids         = var.subnet_ids
        security_group_ids = var.security_group_ids
    }

    tags = {}

    depends_on = [
      aws_iam_role.lambda_role_poc_demo
    ]
}

resource "aws_lambda_permission" "lambda_permissions_poc_demo" {
          
    action        = "lambda:InvokeFunction"
    function_name = "${aws_lambda_function.lambda_function_poc_demo.arn}"
    principal     = "apigateway.amazonaws.com"
    source_arn    = "arn:aws:execute-api:us-east-1:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.api_gateway_rest_api.id}/*/POST/user"
    depends_on    = [aws_lambda_function.lambda_function_poc_demo]
}

resource "aws_api_gateway_rest_api" "api_gateway_rest_api" {
          
    name           = "poc-demo-api-${var.env_type}"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
    tags = {}
}

resource "aws_api_gateway_resource" "api_gateway_resource" {
          
    rest_api_id = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"
    path_part   = "user"
    parent_id   = "${aws_api_gateway_rest_api.api_gateway_rest_api.root_resource_id}"
    depends_on  = [aws_api_gateway_rest_api.api_gateway_rest_api]
}

resource "aws_api_gateway_method_response" "api_gateway_method_response" {
        
  rest_api_id     = aws_api_gateway_rest_api.api_gateway_rest_api.id
  resource_id     = aws_api_gateway_resource.api_gateway_resource.id
  http_method     = aws_api_gateway_method.api_gateway_method.http_method
  status_code     = "200"
  response_models = {
    "application/json" = "Empty"
  }

	depends_on = [
    aws_api_gateway_rest_api.api_gateway_rest_api,
    aws_api_gateway_method.api_gateway_method
  ]
}

resource "aws_api_gateway_method" "api_gateway_method" {
          
    rest_api_id      = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"
    resource_id      = "${aws_api_gateway_resource.api_gateway_resource.id}"
    http_method      = "POST"
    authorization    = "NONE"
    api_key_required = false

    depends_on = [
      aws_api_gateway_rest_api.api_gateway_rest_api,
      aws_api_gateway_resource.api_gateway_resource
    ]
}

resource "aws_api_gateway_integration" "api_gateway_integration" {
        
  rest_api_id             = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"
  resource_id             = "${aws_api_gateway_resource.api_gateway_resource.id}"
  http_method             = "${aws_api_gateway_method.api_gateway_method.http_method}"
  integration_http_method = "POST"
  type                    = "AWS"
  uri                     = "${aws_lambda_function.lambda_function_poc_demo.invoke_arn}"
  request_templates       = {
    "application/json" = jsonencode({
      "sourceIp":"$context.identity.sourceIp",
      "body":"$util.escapeJavaScript($input.json('$'))"
     
    })
  }

  depends_on = [
    aws_api_gateway_rest_api.api_gateway_rest_api,
    aws_api_gateway_resource.api_gateway_resource,
    aws_api_gateway_method.api_gateway_method,
    aws_lambda_function.lambda_function_poc_demo
  ]
}

resource "aws_api_gateway_integration_response" "integration_response" {
        
  rest_api_id        = aws_api_gateway_rest_api.api_gateway_rest_api.id
  resource_id        = aws_api_gateway_resource.api_gateway_resource.id
  http_method        = aws_api_gateway_method.api_gateway_method.http_method
  status_code        = "200"

  depends_on = [
    aws_api_gateway_rest_api.api_gateway_rest_api,
    aws_api_gateway_resource.api_gateway_resource,
    aws_api_gateway_method.api_gateway_method,
    aws_api_gateway_integration.api_gateway_integration
  ]
}

resource "aws_api_gateway_deployment" "api_gateway_deployment" {
        
  rest_api_id = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"
  triggers    = {
    redeployment = sha1(jsonencode([
      "${aws_api_gateway_resource.api_gateway_resource.id}",
      "${aws_api_gateway_method.api_gateway_method.http_method}",
      "${aws_api_gateway_integration.api_gateway_integration.id}",
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_api_gateway_integration.api_gateway_integration]
}

resource "aws_api_gateway_stage" "api_gateway_stage" {
        
  deployment_id = "${aws_api_gateway_deployment.api_gateway_deployment.id}"
  rest_api_id   = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"
  stage_name    = "${var.env_type}"
  depends_on    = [
    aws_api_gateway_deployment.api_gateway_deployment,
    aws_api_gateway_rest_api.api_gateway_rest_api
  ]

  lifecycle {
    ignore_changes = [deployment_id]
  }
}

resource "aws_ssm_parameter" "ssm_max_id" {
          
    name = "/${var.env_type}/poc-demo/maxId"
    type = "String"
    value = "0"

    lifecycle {
      ignore_changes = [value]
    }
}

resource "aws_ssm_parameter" "ssm_thirdparty" {
          
    name  = "/${var.env_type}/poc-demo/thirdparty"
    type  = "String"
    value = jsonencode({
      "domain": "tp.private.com",
    })
}

resource "aws_dynamodb_table" "dynamodb_table" {
            
    attribute {
        name = "id"
        type = "N"
    }

    name           = "poc-demo-audit-${var.env_type}"
    hash_key       = "id"
    read_capacity  = 1
    write_capacity = 1

    global_secondary_index {
        name            = "id-index"
        hash_key        = "id"
        projection_type = "ALL"
        read_capacity   = 1
        write_capacity  = 1
    }

    tags = var.dynamo_backup_tags
}

resource "aws_iam_role" "lambda_role_poc_demo" {
          
    path                 = "/service-role/"
    name                 = "poc-demo-${var.env_type}-role"
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect    = "Allow"
          Principal = {
            Service = "lambda.amazonaws.com"
          }
          Action = "sts:AssumeRole"
        }
      ]
    })
    max_session_duration = 3600
    tags = {}
}

resource "aws_acm_certificate" "custom_domain_certificate" {
        
  domain_name       = var.custom_domain
  validation_method = "DNS"
}

resource "aws_route53_record" "custom_domain_certificate_records_to_validation" {
        
 for_each = {
    for dvo in aws_acm_certificate.custom_domain_certificate.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.domain.zone_id

  depends_on = [aws_acm_certificate.custom_domain_certificate]
}

resource "time_sleep" "wait_50_seconds" {
        
    depends_on = [aws_route53_record.custom_domain_certificate_records_to_validation]
    create_duration = "50s"
}

resource "aws_acm_certificate_validation" "custom_domain_certificate_validation" {
        
  certificate_arn         = aws_acm_certificate.custom_domain_certificate.arn
  validation_record_fqdns = [for record in aws_route53_record.custom_domain_certificate_records_to_validation: record.fqdn]

  depends_on = [time_sleep.wait_50_seconds]
}

resource "aws_apigatewayv2_domain_name" "custom_domain" {
        
  domain_name               = var.custom_domain

  domain_name_configuration {
    certificate_arn  = aws_acm_certificate_validation.custom_domain_certificate_validation.certificate_arn
    security_policy  = "TLS_1_2"
    endpoint_type    = "REGIONAL"
  }

  depends_on = [aws_acm_certificate_validation.custom_domain_certificate_validation]
}

resource "aws_route53_record" "custom_domain_record" {
        
  allow_overwrite = true
  zone_id         = data.aws_route53_zone.domain.zone_id
  name            = var.custom_domain
  type            = "A"

  alias {
    name                   = aws_apigatewayv2_domain_name.custom_domain.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.custom_domain.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }

  depends_on = [aws_apigatewayv2_domain_name.custom_domain]
}

resource "aws_api_gateway_base_path_mapping" "api_gateway_base_path_mapping" {
        
  domain_name        = "${aws_apigatewayv2_domain_name.custom_domain.domain_name}"
  stage_name         = "${aws_api_gateway_stage.api_gateway_stage.stage_name}"
  api_id             = "${aws_api_gateway_rest_api.api_gateway_rest_api.id}"

  depends_on = [
    aws_apigatewayv2_domain_name.custom_domain,
    aws_api_gateway_stage.api_gateway_stage,
    aws_api_gateway_rest_api.api_gateway_rest_api
  ]
}

resource "aws_iam_role_policy_attachment" "policy_attachment_1" {
  role       = aws_iam_role.lambda_role_poc_demo.name
  policy_arn = aws_iam_policy.lambda_basics_poc_demo_policy.arn

  depends_on = [
    aws_iam_role.lambda_role_poc_demo,
    aws_iam_policy.lambda_basics_poc_demo_policy
  ]
}

resource "aws_iam_role_policy_attachment" "policy_attachment_2" {
        
  role       = aws_iam_role.lambda_role_poc_demo.name
  policy_arn = aws_iam_policy.lambda_poc_demo_policy.arn

  depends_on = [
    aws_iam_role.lambda_role_poc_demo,
    aws_iam_policy.lambda_poc_demo_policy
  ]
}

resource "aws_secretsmanager_secret" "sm_thirdparty_creds" {
  name = "/${var.env_type}/poc-demo/sm_thirdparty_creds"
  tags  = {}
}

resource "aws_secretsmanager_secret_version" "set_value_sm_thirdparty_creds" {
  secret_id     = "${aws_secretsmanager_secret.sm_thirdparty_creds.id}"
  secret_string = "{\"client_id\":\"${var.thirdparty_client_id}\", \"client_secret\": \"${var.thirdparty_access_token}\"}"

  depends_on = [
    aws_secretsmanager_secret.sm_thirdparty_creds
  ]
}