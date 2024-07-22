import boto3
from botocore.exceptions import ClientError
from aws.function.source import auto_tagging, constants, utils

GLOBAL_CIDR_IPV4 = "0.0.0.0/0"
GLOBAL_CIDR_IPV6 = "::/0"
ANY_PORT = -1
ANY_PROTOCOL = "-1"

def remediate(session: boto3.Session, event: dict, lambda_context):
    """
    Main Function invoked by index_parser.py
    """
    print("Starting remediation process...")
    
    scan_id = event["scanId"]
    presigned_url = event["presignURL"]

    print(f"Scan ID: {scan_id}")
    print(f"Presigned URL: {presigned_url}")

    response_action_message_list_aggregate = []

    # Remediate the ingress rule allowing any IP source across any port
    response_action_message_list, response_action_status = remediate_security_group_rule(
        session, event, ANY_PROTOCOL, ANY_PORT
    )
    response_action_message_list_aggregate.extend(response_action_message_list)
    response_action_message = ". ".join(response_action_message_list_aggregate)
    print(f"Response action message: {response_action_message}")
    
    if response_action_status == constants.ResponseActionStatus.FAILURE:
        # On failure, just return (inner function takes care of sending error to Wiz)
        utils.send_response_action_result(
            presigned_url, scan_id, response_action_status, response_action_message
        )
        print(f"Remediation failed with message: {response_action_message}")
        return

    # Send result message to Wiz
    if len(response_action_message_list_aggregate) == 0:
        response_action_message = "No matching rules found"
        utils.send_response_action_result(
            presigned_url,
            scan_id,
            constants.ResponseActionStatus.FAILURE,
            response_action_message,
        )
        print(f"No matching rules found. Exiting with message: {response_action_message}")
    else:
        response_action_message = ". ".join(response_action_message_list_aggregate)
        utils.send_response_action_result(
            presigned_url,
            scan_id,
            constants.ResponseActionStatus.SUCCESS,
            response_action_message,
        )
        print(f"Remediation succeeded with message: {response_action_message}")


def remediate_security_group_rule(session, event, protocol_to_remove, port_to_remove):
    sg_id = event["external_id"]
    region = event["region"]
    scan_id = event["scanId"]
    presigned_url = event["presignURL"]
    subscription_id = event["subscription"]["id"]

    print(f"Processing security group {sg_id} in region {region}")

    ec2 = session.client("ec2", region_name=region)

    response_action_message_list = []

    try:
        # Get security group details from ec2
        group = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
        print(f"Security group details: {group}")
    except ClientError as e:
        # Got error, exit and send back error to Wiz
        response_action_message = e.response["Error"]["Message"]
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(f"Error describing security group: {response_action_message}")
        return [response_action_message], response_action_status

    try:
        # Get the security group rules (sgr's) of this security group
        ip_permissions = group[0]["IpPermissions"]
        print(f"IP permissions: {ip_permissions}")
        if len(ip_permissions) == 0:
            # No sgrs, exit with success (another rule might have deleted all sgrs)
            print("No security group rules found.")
            return [], constants.ResponseActionStatus.SUCCESS
    except (IndexError, KeyError):
        # No sgrs, exit and send back error to Wiz
        response_action_message = f"IP permissions not found for security group {sg_id}"
        response_action_status = constants.ResponseActionStatus.FAILURE
        print(f"Error: {response_action_message}")
        return [response_action_message], response_action_status

    # Go over sgrs and try to find one that matches our criteria
    for ip_permission in ip_permissions:
        ip_protocol = ip_permission["IpProtocol"]

        # Skip this sgr if it is not in the correct protocol and not -1 (-1 means any protocol)
        if ip_protocol not in ("-1", protocol_to_remove, "tcp", "udp"):
            print(f"Skipping rule due to protocol mismatch: {ip_protocol}")
            continue

        # Handle case of no FromPort (caused by default security rule)
        if "FromPort" in ip_permission:
            from_port = ip_permission["FromPort"]
            to_port = ip_permission["ToPort"]
        else:
            from_port = ANY_PORT
            to_port = ANY_PORT

        print(f"Evaluating rule: protocol={ip_protocol}, from_port={from_port}, to_port={to_port}")

        remove = False

        # Remove if protocol to remove is -1 and this sgr's protocol is also -1
        if ip_protocol == ANY_PROTOCOL and protocol_to_remove == ANY_PROTOCOL:
            remove = True

        # Remove this sgr if it is the any port sgr
        if from_port == ANY_PORT and to_port == ANY_PORT:
            remove = True

        # Remove if the port range covers any ports
        if from_port == 0 and to_port == 65535:
            remove = True

        # Skip this sgr if the port we are looking for is not in this sgr range
        if not remove:
            print(f"Skipping rule due to port range mismatch: from_port={from_port}, to_port={to_port}")
            continue

        # Go over ipv4 ranges and remove sgr only if it is in the range we are looking for
        for ip_range in ip_permission.get("IpRanges", []):
            if ip_range["CidrIp"] == GLOBAL_CIDR_IPV4:
                try:
                    msg = remove_security_group_rule(
                        ec2,
                        sg_id,
                        ip_protocol,
                        from_port,
                        to_port,
                        "IpRanges",
                        "CidrIp",
                        ip_range["CidrIp"],
                    )
                    response_action_message_list.append(msg)
                    print(f"Removed IPv4 rule: {msg}")
                    auto_tagging.autotag_ec2(
                        sg_id, region, subscription_id, presigned_url, scan_id
                    )
                except ClientError as e:
                    # Something went wrong, exit with failure
                    response_action_message = e.response["Error"]["Message"]
                    response_action_status = constants.ResponseActionStatus.FAILURE
                    print(f"Error removing IPv4 rule: {response_action_message}")
                    return [response_action_message], response_action_status

        # Go over ipv6 ranges and remove sgr only if it is in the range we are looking for
        for ip_range in ip_permission.get("Ipv6Ranges", []):
            if ip_range["CidrIpv6"] == GLOBAL_CIDR_IPV6:
                try:
                    msg = remove_security_group_rule(
                        ec2,
                        sg_id,
                        ip_protocol,
                        from_port,
                        to_port,
                        "Ipv6Ranges",
                        "CidrIpv6",
                        ip_range["CidrIpv6"],
                    )
                    response_action_message_list.append(msg)
                    print(f"Removed IPv6 rule: {msg}")
                    auto_tagging.autotag_ec2(
                        sg_id, region, subscription_id, presigned_url, scan_id
                    )
                except ClientError as e:
                    # Something went wrong, exit with failure
                    response_action_message = e.response["Error"]["Message"]
                    response_action_status = constants.ResponseActionStatus.FAILURE
                    print(f"Error removing IPv6 rule: {response_action_message}")
                    return [response_action_message], response_action_status

    return response_action_message_list, constants.ResponseActionStatus.SUCCESS


def remove_security_group_rule(
    ec2, sg_id, ip_protocol, from_port, to_port, ip_ranges, ip_cidr_key, ip_cidr_value
):
    revoke_args = {
        "GroupId": sg_id,
        "IpPermissions": [
            {"IpProtocol": ip_protocol, ip_ranges: [{ip_cidr_key: ip_cidr_value}]}
        ],
    }

    # Add FromPort and ToPort to revoke arguments only if the sgr to be removed contains these
    if from_port != ANY_PORT or ip_protocol == "icmp" or ip_protocol == ANY_PROTOCOL:
        revoke_args["IpPermissions"][0]["FromPort"] = from_port

    if to_port != ANY_PORT or ip_protocol == "icmp" or ip_protocol == ANY_PROTOCOL:
        revoke_args["IpPermissions"][0]["ToPort"] = to_port

    print(f"Revoking rule: {revoke_args}")

    # We don't try-except here since it should be caught by caller
    ec2.revoke_security_group_ingress(**revoke_args)

    msg = f'Revoked rule permitting {"any" if ip_protocol == "-1" else ip_protocol}/{"any" if from_port == ANY_PORT else from_port}-{"any" if to_port == ANY_PORT else to_port} with cidr {ip_cidr_value} from {sg_id}'
    print(msg)
    return msg
