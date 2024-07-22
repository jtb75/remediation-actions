import boto3
from botocore.exceptions import ClientError
from aws.function.source import auto_tagging, constants, utils


def get_public_access_block(s3_client, s3_id):
    print(f"Getting public access block configuration for bucket: {s3_id}")
    try:
        response = s3_client.get_public_access_block(Bucket=s3_id)
        print(f"Received response for get_public_access_block: {response}")
    except ClientError as e:
        response_action_message = e.response["Error"]["Message"]
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(f"Error getting public access block: {response_action_message}")
        return response_action_message, response_action_status, None

    if "PublicAccessBlockConfiguration" in response:
        public_access_block_conf = response["PublicAccessBlockConfiguration"]
        print(
            f"Current PublicAccessBlockConfiguration for the bucket:\n {public_access_block_conf}"
        )
    else:
        response_action_message = (
            f"Got invalid response for get_public_access_block: {response}"
        )
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(response_action_message)
        return response_action_message, response_action_status, None

    return "", constants.ResponseActionStatus.SUCCESS, public_access_block_conf


def set_public_access_block_true(s3_client, s3_id):
    print(f"Setting public access block configuration to true for bucket: {s3_id}")
    try:
        s3_client.put_public_access_block(
            Bucket=s3_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        print(f"Successfully set public access block configuration for bucket: {s3_id}")
    except ClientError as e:
        response_action_message = e.response["Error"]["Message"]
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(f"Error setting public access block: {response_action_message}")
        return response_action_message, response_action_status

    return "", constants.ResponseActionStatus.SUCCESS


def remediate(session: boto3.Session, event: dict, lambda_context):
    """
    Main Function invoked by index_parser.py
    """
    print("Starting remediation process...")
    print(event)
    s3_id = event["external_id"]
    region = event["region"]
    scan_id = event["scanId"]
    presigned_url = event["presignURL"]
    subscription_id = event["subscription"]["id"]

    print(f"S3 Bucket ID: {s3_id}")
    print(f"Region: {region}")
    print(f"Scan ID: {scan_id}")
    print(f"Presigned URL: {presigned_url}")
    print(f"Subscription ID: {subscription_id}")

    s3_client = session.client("s3", region_name=region)

    # get the current public access block to print and log
    print("Getting current public access block configuration...")
    response_action_message, response_action_status, _ = get_public_access_block(
        s3_client, s3_id
    )
    if response_action_status == constants.ResponseActionStatus.FAILURE:
        print(f"Failed to get current public access block configuration: {response_action_message}")
        utils.send_response_action_result(
            presigned_url, scan_id, response_action_status, response_action_message
        )
        return

    # update the public access block
    print("Setting public access block configuration to true...")
    response_action_message, response_action_status = set_public_access_block_true(
        s3_client, s3_id
    )
    if response_action_status == constants.ResponseActionStatus.FAILURE:
        print(f"Failed to set public access block configuration: {response_action_message}")
        utils.send_response_action_result(
            presigned_url, scan_id, response_action_status, response_action_message
        )
        return

    response_action_message = f"Successfully restricted bucket {s3_id} public access and set all PublicAccessBlockConfiguration options to True."
    response_action_status = constants.ResponseActionStatus.SUCCESS

    print(response_action_message)
    utils.send_response_action_result(
        presigned_url, scan_id, response_action_status, response_action_message
    )

    print(f"Auto-tagging S3 bucket: {s3_id}")
    auto_tagging.autotag_s3_bucket(
        s3_id, region, subscription_id, presigned_url, scan_id
    )
    print("Remediation process completed.")
