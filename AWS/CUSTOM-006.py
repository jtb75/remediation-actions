import boto3
from botocore.exceptions import ClientError
from aws.function.source import auto_tagging, constants, utils

def remediate(session, alert, lambda_context):
    """
    Args:
        session (boto3.Session): The Boto3 session to use for AWS interactions.
        alert (dict): The alert data containing information about the Lambda function.
        lambda_context (LambdaContext): The context in which the Lambda function is executed.
    """
    # Extract relevant information from the alert
    scan_id = alert['scanId']
    presigned_url = alert['presignURL']
    region = alert['region']
    ami_id = alert['external_id']
    
    print(f"Starting remediation process for AMI {ami_id} in region {region}")
    print(f"Scan ID: {scan_id}")
    print(f"Presigned URL: {presigned_url}")

    ec2_client = session.client('ec2', region_name=region)

    try:
        # Check current permissions for the AMI
        print(f"Checking current launch permissions for AMI {ami_id}")
        response = ec2_client.describe_image_attribute(
            Attribute='launchPermission',
            ImageId=ami_id
        )
        print(f"Current launch permissions: {response['LaunchPermissions']}")

        # Remove public launch permission
        print(f"Revoking public access for AMI {ami_id}")
        ec2_client.modify_image_attribute(
            ImageId=ami_id,
            LaunchPermission={
                'Remove': [
                    {'Group': 'all'}
                ]
            }
        )

        # Verify that the public access has been removed
        response = ec2_client.describe_image_attribute(
            Attribute='launchPermission',
            ImageId=ami_id
        )
        print(f"Updated launch permissions: {response['LaunchPermissions']}")
        
        response_action_message = f"Public access removed from AMI {ami_id} successfully"
        response_action_status = constants.ResponseActionStatus.SUCCESS
        print(response_action_message)
    except ClientError as e:
        response_action_message = f"Error modifying AMI permissions: {e}"
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(response_action_message)

    # Send the response action result to the presigned URL and log the action
    utils.send_response_action_result(presigned_url, scan_id, response_action_status, response_action_message)
