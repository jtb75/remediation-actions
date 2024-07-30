import boto3
from botocore.exceptions import ClientError
from aws.function.source import auto_tagging, constants, utils

def remediate(session, alert, lambda_context):
    """
    Remediate the specified AWS Lambda function to update URL auth type to "AWS_IAM".
    
    Required Permissions:
    - lambda:ListFunctions
    - lambda:GetFunction
    - lambda:UpdateFunctionUrlConfig
    
    Args:
        session (boto3.Session): The Boto3 session to use for AWS interactions.
        alert (dict): The alert data containing information about the Lambda function.
        lambda_context (LambdaContext): The context in which the Lambda function is executed.
    """
    # Extract relevant information from the alert
    scan_id = alert['scanId']
    presigned_url = alert['presignURL']
    region = alert['region']
    lambda_id = alert['external_id']
    
    print(f"Starting remediation process for Lambda {lambda_id} in region {region}")
    print(f"Scan ID: {scan_id}")
    print(f"Presigned URL: {presigned_url}")

    try:
        # Initialize Lambda client
        lambda_client = session.client('lambda', region_name=region)
        
        # Extract function name from the ARN
        function_name = lambda_id.split(':')[-1]
        print(f"Function name extracted: {function_name}")

        # Get the list of Lambda functions (lambda:ListFunctions permission required)
        print("Listing Lambda functions...")
        functions = lambda_client.list_functions()
        print(f"Functions listed: {functions}")

        # Verify the function exists (lambda:GetFunction permission required)
        print(f"Verifying the existence of function: {lambda_id}")
        lambda_client.get_function(FunctionName=lambda_id)
        print(f"Function {lambda_id} verified to exist.")

        # Update the function URL auth type (lambda:UpdateFunctionUrlConfig permission required)
        print(f"Updating URL auth type for function: {lambda_id}")
        response = lambda_client.update_function_url_config(
            FunctionName=lambda_id,
            AuthType='AWS_IAM'
        )
        print(f"Updated URL auth type response: {response}")
        response_action_message = f"Public access removed from Lambda function {function_name} successfully"
        response_action_status = constants.ResponseActionStatus.SUCCESS
    
    except ClientError as e:
        print(f"Error updating URL auth type for function: {lambda_id}")
        print(e)
        response_action_message = f"Failed to remove public access from Lambda function {function_name}: {str(e)}"
        response_action_status = constants.ResponseActionStatus.FAILURE

    # Send the response action result to the presigned URL and log the action
    utils.send_response_action_result(presigned_url, scan_id, response_action_status, response_action_message)
    print(response_action_message)
