from botocore.exceptions import ClientError
from aws.function.source import auto_tagging
from aws.function.source import utils
from aws.function.source import constants

def shutdown_instance(session, instance_id, region):
    """
    Shuts down the specified EC2 instance.

    Args:
        instance_id (str): The ID of the EC2 instance.
        region (str): The AWS region where the instance is located.
    """
    try:
        ec2_client = session.client('ec2', region_name=region)
        
        # Log the instance shutdown request
        print(f"Attempting to shutdown EC2 instance: {instance_id} in region: {region}")
        
        # Stop the instance
        response = ec2_client.stop_instances(InstanceIds=[instance_id])
        
        # Log the response
        print(f"Shutdown response: {response}")
        
        # Wait for the instance to enter the 'stopped' state
        waiter = ec2_client.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])
        
        # Log the instance stopped state
        print(f"Instance {instance_id} is now stopped.")
    
    except ClientError as e:
        print(f"ClientError while shutting down the instance: {e}")
    except Exception as e:
        print(f"An error occurred while shutting down the instance: {e}")

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

    # Extract instance ID and region from alert metadata
    resource_name = alert['metadata']['name']
    instance_id = alert['metadata']['externalId']
    region = alert['metadata']['region']
    print(f"Extracted EC2 name: {resource_name} and region: {region} from alert metadata")

    # Poweroff 
    shutdown_instance(session, instance_id, region)

    # Send the response action result to the presigned URL and log the action
    response_action_message = f"Resource {resource_name} remediated successfully"
    response_action_status = constants.ResponseActionStatus.SUCCESS
    print(response_action_message)
    utils.send_response_action_result(presigned_url, scan_id, response_action_status, response_action_message)
