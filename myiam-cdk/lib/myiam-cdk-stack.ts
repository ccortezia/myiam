import * as cdk from '@aws-cdk/core'
import * as lambda from "@aws-cdk/aws-lambda"
import * as lambdaEventSources from "@aws-cdk/aws-lambda-event-sources"
import * as dynamodb from "@aws-cdk/aws-dynamodb"
import * as iam from "@aws-cdk/aws-iam"

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
      code: lambda.Code.fromAsset("resources/lambdas"),
      handler: "ddb_stream_handler.handle",
      runtime: lambda.Runtime.PYTHON_3_7,
      initialPolicy: [
        new iam.PolicyStatement({
          sid: "AllowLambdaToQueryDynamoDbTable",
          effect: iam.Effect.ALLOW,
          actions: ["dynamodb:Query", "dynamodb:PutItem", "dynamodb:DeleteItem"],
          resources: ["arn:aws:dynamodb:us-east-1:583723262561:table/myiam"]
        })
      ]
    })

    streamHandler.addEventSource(new lambdaEventSources.DynamoEventSource(table, {
      startingPosition: lambda.StartingPosition.LATEST
    }))
  }
}
