def get_new_events(table, dynamodbstreams, iterator=None):
    # NOTE: This function will be moved to whatever project hosts the stream lambdas.
    # NOTE: this is a simplified event-fetching routine to support local tests.
    if not iterator:
        dynamodbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        response = dynamodbstreams.describe_stream(StreamArn=table.latest_stream_arn)
        shard_id = response["StreamDescription"]["Shards"][0]["ShardId"]
        response = dynamodbstreams.get_shard_iterator(
            StreamArn=table.latest_stream_arn, ShardIteratorType="TRIM_HORIZON", ShardId=shard_id
        )
        iterator = response["ShardIterator"]
    response = dynamodbstreams.get_records(ShardIterator=iterator)
    new_iterator = response.get("NextShardIterator")
    return response["Records"], new_iterator
