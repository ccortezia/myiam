# NOTE: these comments are notes to support writing tests for the stream handler, eventually.

# UPDATE GROUP ADD USERS
# {
#     "Records": [
#         {
#             "eventID": "f72b109d9f8bc284d9bd4524f985098a",
#             "eventName": "INSERT",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608723751,
#                 "Keys": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "NewImage": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289057600000000021417857437",
#                 "SizeBytes": 60,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }

# UPDATE GROUP ATTACH POLICIES
#     "Records": [
#         {
#             "eventID": "ab1ac480a4986f7ebd28cb85800257a3",
#             "eventName": "INSERT",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608723817,
#                 "Keys": {
#                     "sk": {
#                         "S": "policy#PolicyA"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "NewImage": {
#                     "sk": {
#                         "S": "policy#PolicyA"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289057700000000021417882339",
#                 "SizeBytes": 60,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         },
#         {
#             "eventID": "2e8b30ed2ce2f298bcbce741c496e7d7",
#             "eventName": "INSERT",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608723817,
#                 "Keys": {
#                     "sk": {
#                         "S": "policy#PolicyB"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "NewImage": {
#                     "sk": {
#                         "S": "policy#PolicyB"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289057800000000021417882341",
#                 "SizeBytes": 60,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }

# UPDATE GROUP DETACH POLICIES
# {
#     "Records": [
#         {
#             "eventID": "c938f511dc65f353ac82147b578b94c5",
#             "eventName": "REMOVE",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608723895,
#                 "Keys": {
#                     "sk": {
#                         "S": "policy#PolicyB"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289057900000000021417911854",
#                 "SizeBytes": 30,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }

# UPDATE GROUP REMOVE USERS
# {
#     "Records": [
#         {
#             "eventID": "bbccd8a10d8a44a2fba2b966ba488eb0",
#             "eventName": "REMOVE",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608723944,
#                 "Keys": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289058000000000021417929826",
#                 "SizeBytes": 30,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }

# UPDATE USER ADD TO GROUP
# {
#     "Records": [
#         {
#             "eventID": "00e556008cccbe6c56a41b3275e36455",
#             "eventName": "INSERT",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608726207,
#                 "Keys": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "NewImage": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group1"
#                     }
#                 },
#                 "SequenceNumber": "289058100000000021418855856",
#                 "SizeBytes": 60,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }

# UPDATE USER REMOVE FROM GROUP
# {
#     "Records": [
#         {
#             "eventID": "e6c38703c6bf6b1d047e4119ab9f625e",
#             "eventName": "REMOVE",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608726625,
#                 "Keys": {
#                     "sk": {
#                         "S": "user#ccortezia"
#                     },
#                     "pk": {
#                         "S": "group#group2"
#                     }
#                 },
#                 "SequenceNumber": "289242300000000038535135672",
#                 "SizeBytes": 30,
#                 "StreamViewType": "NEW_IMAGE"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-10-23T17:32:41.260"
#         }
#     ]
# }


# UPDATE POLICY SET DEFAULT VERSION
# {
#     "Records": [
#         {
#             "eventID": "f1876bb1a9f8deee9242721a35307c21",
#             "eventName": "MODIFY",
#             "eventVersion": "1.1",
#             "eventSource": "aws:dynamodb",
#             "awsRegion": "us-east-1",
#             "dynamodb": {
#                 "ApproximateCreationDateTime": 1608992548,
#                 "Keys": {
#                     "sk": {
#                         "S": "policy#control"
#                     },
#                     "pk": {
#                         "S": "policy#PolicyA"
#                     }
#                 },
#                 "NewImage": {
#                     "versions": {
#                         "N": "2"
#                     },
#                     "default_version": {
#                         "N": "1"
#                     },
#                     "sk": {
#                         "S": "policy#control"
#                     },
#                     "pk": {
#                         "S": "policy#PolicyA"
#                     }
#                 },
#                 "OldImage": {
#                     "versions": {
#                         "N": "2"
#                     },
#                     "default_version": {
#                         "N": "2"
#                     },
#                     "sk": {
#                         "S": "policy#control"
#                     },
#                     "pk": {
#                         "S": "policy#PolicyA"
#                     }
#                 },
#                 "SequenceNumber": "304010400000000042909974419",
#                 "SizeBytes": 150,
#                 "StreamViewType": "NEW_AND_OLD_IMAGES"
#             },
#             "eventSourceARN": "arn:aws:dynamodb:us-east-1:583723262561:table/myiam/stream/2020-12-26T14:04:41.068"
#         }
#     ]
# }
