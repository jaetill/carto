# REST API: CartoAPI (9o7c3668a4)

resource "aws_api_gateway_rest_api" "carto_rest" {
  name             = "CartoAPI"
  api_key_source   = "HEADER"
  endpoint_configuration {
    types = ["EDGE"]
  }
}

resource "aws_api_gateway_authorizer" "carto_rest_cartosharedpool" {
  name            = "CartoSharedPool"
  rest_api_id     = aws_api_gateway_rest_api.carto_rest.id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = ["arn:aws:cognito-idp:us-east-2:214599503944:userpool/us-east-2_xneeJzaDJ"]
  identity_source = "method.request.header.Authorization"
}

resource "aws_api_gateway_resource" "carto_rest_engagement_id_snapshots" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  parent_id   = aws_api_gateway_rest_api.carto_rest.root_resource_id
  path_part   = "snapshots"
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_snapshots_get" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method      = "GET"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_snapshots_get" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_snapshots_get.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "37ysc6"
  cache_key_parameters = []
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_snapshots_options" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_snapshots_options" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_snapshots_options.http_method
  type                 = "MOCK"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "37ysc6"
  cache_key_parameters = []
  request_templates = {
    "application/json" = "{\"statusCode\":200}"
  }
}

resource "aws_api_gateway_method_response" "carto_rest_engagement_id_snapshots_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method = aws_api_gateway_method.carto_rest_engagement_id_snapshots_options.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = false
    "method.response.header.Access-Control-Allow-Methods" = false
    "method.response.header.Access-Control-Allow-Origin" = false
  }
}

resource "aws_api_gateway_integration_response" "carto_rest_engagement_id_snapshots_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method = aws_api_gateway_method.carto_rest_engagement_id_snapshots_options.http_method
  status_code = aws_api_gateway_method_response.carto_rest_engagement_id_snapshots_options_200.status_code
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Authorization,Content-Type'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }
  depends_on = [aws_api_gateway_integration.carto_rest_engagement_id_snapshots_options]
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_snapshots_post" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method      = "POST"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_snapshots_post" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_snapshots.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_snapshots_post.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "37ysc6"
  cache_key_parameters = []
}

resource "aws_api_gateway_resource" "carto_rest_engagement_id_data" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  parent_id   = aws_api_gateway_rest_api.carto_rest.root_resource_id
  path_part   = "data"
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_data_get" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method      = "GET"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_data_get" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_data_get.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "57l8fk"
  cache_key_parameters = []
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_data_options" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_data_options" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_data_options.http_method
  type                 = "MOCK"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "57l8fk"
  cache_key_parameters = []
  request_templates = {
    "application/json" = "{\"statusCode\":200}"
  }
}

resource "aws_api_gateway_method_response" "carto_rest_engagement_id_data_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method = aws_api_gateway_method.carto_rest_engagement_id_data_options.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = false
    "method.response.header.Access-Control-Allow-Methods" = false
    "method.response.header.Access-Control-Allow-Origin" = false
  }
}

resource "aws_api_gateway_integration_response" "carto_rest_engagement_id_data_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method = aws_api_gateway_method.carto_rest_engagement_id_data_options.http_method
  status_code = aws_api_gateway_method_response.carto_rest_engagement_id_data_options_200.status_code
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Authorization,Content-Type'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }
  depends_on = [aws_api_gateway_integration.carto_rest_engagement_id_data_options]
}

resource "aws_api_gateway_method" "carto_rest_engagement_id_data_post" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method      = "POST"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagement_id_data_post" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagement_id_data.id
  http_method          = aws_api_gateway_method.carto_rest_engagement_id_data_post.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "57l8fk"
  cache_key_parameters = []
}

resource "aws_api_gateway_resource" "carto_rest_engagements" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  parent_id   = aws_api_gateway_rest_api.carto_rest.root_resource_id
  path_part   = "engagements"
}

resource "aws_api_gateway_method" "carto_rest_engagements_get" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagements.id
  http_method      = "GET"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagements_get" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagements.id
  http_method          = aws_api_gateway_method.carto_rest_engagements_get.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "p7c2q0"
  cache_key_parameters = []
}

resource "aws_api_gateway_method" "carto_rest_engagements_options" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagements.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagements_options" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagements.id
  http_method          = aws_api_gateway_method.carto_rest_engagements_options.http_method
  type                 = "MOCK"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "p7c2q0"
  cache_key_parameters = []
  request_templates = {
    "application/json" = "{\"statusCode\":200}"
  }
}

resource "aws_api_gateway_method_response" "carto_rest_engagements_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagements.id
  http_method = aws_api_gateway_method.carto_rest_engagements_options.http_method
  status_code = "200"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = false
    "method.response.header.Access-Control-Allow-Methods" = false
    "method.response.header.Access-Control-Allow-Origin" = false
  }
}

resource "aws_api_gateway_integration_response" "carto_rest_engagements_options_200" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  resource_id = aws_api_gateway_resource.carto_rest_engagements.id
  http_method = aws_api_gateway_method.carto_rest_engagements_options.http_method
  status_code = aws_api_gateway_method_response.carto_rest_engagements_options_200.status_code
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Authorization,Content-Type'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }
  depends_on = [aws_api_gateway_integration.carto_rest_engagements_options]
}

resource "aws_api_gateway_method" "carto_rest_engagements_post" {
  rest_api_id      = aws_api_gateway_rest_api.carto_rest.id
  resource_id      = aws_api_gateway_resource.carto_rest_engagements.id
  http_method      = "POST"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.carto_rest_cartosharedpool.id
  api_key_required = false
}

resource "aws_api_gateway_integration" "carto_rest_engagements_post" {
  rest_api_id          = aws_api_gateway_rest_api.carto_rest.id
  resource_id          = aws_api_gateway_resource.carto_rest_engagements.id
  http_method          = aws_api_gateway_method.carto_rest_engagements_post.http_method
  type                 = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:us-east-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-2:214599503944:function:cartoApi/invocations"
  integration_http_method = "POST"
  passthrough_behavior = "WHEN_NO_MATCH"
  timeout_milliseconds = 29000
  cache_namespace      = "p7c2q0"
  cache_key_parameters = []
}

resource "aws_api_gateway_deployment" "carto_rest_prod" {
  rest_api_id = aws_api_gateway_rest_api.carto_rest.id
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [triggers]
  }
}

resource "aws_api_gateway_stage" "carto_rest_prod" {
  rest_api_id   = aws_api_gateway_rest_api.carto_rest.id
  stage_name    = "prod"
  deployment_id = aws_api_gateway_deployment.carto_rest_prod.id
}


# ============================================================================
# Lambda permission
# ============================================================================

resource "aws_lambda_permission" "apigw_cartoapi" {
  statement_id  = "apigateway-invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cartoapi.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.aws_region}:${var.aws_account_id}:${aws_api_gateway_rest_api.carto_rest.id}/*/*"
}