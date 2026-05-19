import {
  to = aws_secretsmanager_secret.main
  id = "arn:aws:secretsmanager:us-east-2:214599503944:secret:carto/secrets-qgjImO"
}

import {
  to = aws_cloudwatch_log_group.cartoapi
  id = "/aws/lambda/cartoApi"
}