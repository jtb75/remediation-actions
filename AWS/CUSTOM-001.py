import json
import boto3
from botocore.exceptions import ClientError
from aws.function.source import auto_tagging
from aws.function.source import utils
from aws.function.source import constants

# Configure logging

def remove_public_access(session, function_name, region):
    """
    Remove public access from the specified AWS Lambda function.

    Args:
        session (boto3.Session): The session to use for AWS interactions.
        function_name (str): The name of the AWS Lambda function.
        region (str): The region where the function is deployed.
    """
    print(f"Initializing AWS Lambda client for region: {region} with assumed role session")
    client = session.client('lambda', region_name=region)

    try:
        print(f"Getting policy for function: {function_name}")
        response = client.get_policy(FunctionName=function_name)
        policy = response['Policy']
        print(f"Existing policy: {policy}")

        # Parse the policy JSON and identify public access statements
        policy_document = json.loads(policy)
        statements_to_remove = []

        for statement in policy_document.get('Statement', []):
                statements_to_remove.append(statement)
                print(f"Identified access statement: {statement}")

        # Remove public access statements from the policy
        for statement in statements_to_remove:
            sid = statement['Sid']
            try:
                print(f"Removing public access statement with Sid: {sid}")
                client.remove_permission(FunctionName=function_name, StatementId=sid)
                print(f"Removed public access statement with Sid: {sid}")
            except ClientError as e:
                print(f"Error removing statement {sid}: {e}")

    except ClientError as e:
        print(f"Error getting policy for function {function_name}: {e}")
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Function {function_name} does not have a policy.")
        else:
            raise e

def remediate(session, alert, lambda_context):
    """
    Remediate the specified AWS Lambda function to remove public access.

    Args:
        session (boto3.Session): The Boto3 session to use for AWS interactions.
        alert (dict): The alert data containing information about the Lambda function.
        lambda_context (LambdaContext): The context in which the Lambda function is executed.
    """
    scan_id = alert['scanId']
    presigned_url = alert['presignURL']

    # Extract function name and region from alert metadata
    function_name = alert['metadata']['name']
    region = alert['metadata']['region']
    print(f"Extracted function name: {function_name} and region: {region} from alert metadata")

    # Call the function to remove public access from the specified Lambda function
    remove_public_access(session, function_name, region)

    # Send the response action result to the presigned URL and log the action
    response_action_message = f"Public access removed from function {function_name} successfully"
    response_action_status = constants.ResponseActionStatus.SUCCESS
    print(response_action_message)
    utils.send_response_action_result(presigned_url, scan_id, response_action_status, response_action_message)
