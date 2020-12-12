import * as cdk from '@aws-cdk/core'
import * as lambda from "@aws-cdk/aws-lambda"
import * as lambdaEventSources from "@aws-cdk/aws-lambda-event-sources"
import * as dynamodb from "@aws-cdk/aws-dynamodb"
import * as iam from "@aws-cdk/aws-iam"
import * as apig from "@aws-cdk/aws-apigateway"

export class MyIamCdkStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props)

    const table = new dynamodb.Table(this, "MyIamDdbTable", {
      tableName: "myiam",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      stream: dynamodb.StreamViewType.NEW_IMAGE,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    })

    table.addGlobalSecondaryIndex({
      indexName: "sk_pk",
      partitionKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    })

    table.addGlobalSecondaryIndex({
      indexName: "action_lookup",
      partitionKey: { name: "rule_action", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "rule_effect", type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    })

    const streamHandler = new lambda.Function(this, "MyIamDdbStreamHandler", {
      functionName: "MyIamDdbStreamHandler",
      code: lambda.Code.fromAsset("resources/lambdas/ddb_stream_handler"),
      handler: "handler.handle",
      runtime: lambda.Runtime.PYTHON_3_8,
      initialPolicy: [
        new iam.PolicyStatement({
          sid: "AllowLambdaToQueryDynamoDbTable",
          effect: iam.Effect.ALLOW,
          actions: ["dynamodb:Query", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"],
          resources: ["arn:aws:dynamodb:us-east-1:583723262561:table/myiam*"]
        })
      ]
    })

    streamHandler.addEventSource(new lambdaEventSources.DynamoEventSource(table, {
      startingPosition: lambda.StartingPosition.LATEST
    }))

    // NOTE: temporarily here for experimental purposes.
    const apiLayer = new lambda.LayerVersion(this, "MyIamApiLayer", {
      layerVersionName: "myiam-api",
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_8],
      code: new lambda.AssetCode("resources/layers/myiam_api/build/layer.zip")
    })

    const apiHandler = new lambda.Function(this, "MyIamAdminApiHandler", {
      functionName: "MyIamAdminApiHandler",
      code: lambda.Code.fromAsset("resources/lambdas/api"),
      handler: "handler.handle",
      runtime: lambda.Runtime.PYTHON_3_8,
      layers: [apiLayer],
      initialPolicy: [
        new iam.PolicyStatement({
          sid: "AllowLambdaToQueryDynamoDbTable",
          effect: iam.Effect.ALLOW,
          actions: ["dynamodb:Scan", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:DeleteItem"],
          resources: ["arn:aws:dynamodb:us-east-1:583723262561:table/myiam*"]
        })
      ]
    })

    const authorizerLayer = new lambda.LayerVersion(this, "MyIamApiAuthorizerLayer", {
      layerVersionName: "myiam-authorizer",
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_8],
      code: new lambda.AssetCode("resources/layers/authorizer/build/layer.zip")
    })

    const authorizerLambda = new lambda.Function(this, "MyIamApiAuthorizerLambda", {
      functionName: "MyIamApiAuthorizerLambda",
      runtime: lambda.Runtime.PYTHON_3_8,
      layers: [authorizerLayer],
      code: lambda.Code.fromAsset('resources/lambdas/authorizer'),
      handler: "handler.handle",
      initialPolicy: [
        new iam.PolicyStatement({
          sid: "AllowLambdaToQueryDynamoDbTable",
          effect: iam.Effect.ALLOW,
          actions: ["dynamodb:Scan", "dynamodb:Query"],
          resources: ["arn:aws:dynamodb:us-east-1:583723262561:table/myiam*"],
        })
      ]
    })

    const authorizer = new apig.RequestAuthorizer(this, "MyIamRequestAuthorizer", {
      authorizerName: "MyIamRequestAuthorizer",
      handler: authorizerLambda,
      identitySources: [apig.IdentitySource.header('Authorizer')],
      resultsCacheTtl: cdk.Duration.minutes(0),
    })

    const api = new apig.LambdaRestApi(this, "MyIamRestApi", {
      handler: apiHandler,
      defaultMethodOptions: {
        authorizationType: apig.AuthorizationType.CUSTOM,
        authorizer
      }
    })
  }
}
