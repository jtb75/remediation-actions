import re
import logging
from google.cloud import functions_v1, run_v2
from google.api_core.exceptions import NotFound, GoogleAPICallError
from google.iam.v1 import policy_pb2

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def remove_public_access_gen2(client, resource_name):
    """
    Remove specified members from multiple roles of a Google Cloud Run service's IAM policy.
    
    Args:
        client (run_v2.ServicesClient): Client to interact with Google Cloud Run API.
        resource_name (str): Full resource name of the Cloud Run service.
    
    Returns:
        bool: True if the policy was updated successfully, False otherwise.
    """
    try:
        # Fetch the current IAM policy
        policy = client.get_iam_policy(request={"resource": resource_name})

        # Define the roles and members to remove
        roles_to_remove = ["roles/run.invoker"]
        members_to_remove = ["allUsers", "allAuthenticatedUsers"]
        
        # Track changes
        changes_made = False
        
        # Iterate over all bindings and remove specified members from specified roles
        for binding in list(policy.bindings):  # Use list to clone the iterable for safe removal
            if binding.role in roles_to_remove:
                original_members = set(binding.members)
                # Remove specified members
                binding.members[:] = [m for m in binding.members if m not in members_to_remove]
                # Check if changes were made
                if set(binding.members) != original_members:
                    changes_made = True
                # Remove the binding if it's empty
                if not binding.members:
                    policy.bindings.remove(binding)
        
        # Update the IAM policy if changes were made
        if changes_made:
            client.set_iam_policy(request={"resource": resource_name, "policy": policy})
        return changes_made
    except (GoogleAPICallError, NotFound) as e:
        logger.error(f"Failed to update IAM policy for Cloud Run service {resource_name}: {e}")
        return False

def remove_public_access_v1(client, resource_name):
    """
    Remove specified members from multiple roles of a Google Cloud Function's IAM policy (1st gen).
    
    Args:
        client (functions_v1.CloudFunctionsServiceClient): Client to interact with Google Cloud Functions API.
        resource_name (str): Full resource name of the Cloud Function.
    
    Returns:
        bool: True if the policy was updated successfully, False otherwise.
    """
    try:
        # Fetch the current IAM policy
        policy = client.get_iam_policy(request={"resource": resource_name})

        # Define the roles and members to remove
        roles_to_remove = ["roles/cloudfunctions.invoker"]
        members_to_remove = ["allUsers", "allAuthenticatedUsers"]
        
        # Track changes
        changes_made = False
        
        # Iterate over all bindings and remove specified members from specified roles
        for binding in list(policy.bindings):  # Use list to clone the iterable for safe removal
            if binding.role in roles_to_remove:
                original_members = set(binding.members)
                # Remove specified members
                binding.members[:] = [m for m in binding.members if m not in members_to_remove]
                # Check if changes were made
                if set(binding.members) != original_members:
                    changes_made = True
                # Remove the binding if it's empty
                if not binding.members:
                    policy.bindings.remove(binding)
        
        # Update the IAM policy if changes were made
        if changes_made:
            client.set_iam_policy(request={"resource": resource_name, "policy": policy})
        return changes_made
    except (GoogleAPICallError, NotFound) as e:
        logger.error(f"Failed to update IAM policy for Cloud Function {resource_name}: {e}")
        return False

def parse_gcp_url(url):
    """
    Parses a GCP Cloud Run or Cloud Functions URL and returns a dictionary with function/service name,
    region, generation, and project.

    Args:
        url (str): The URL to parse.

    Returns:
        dict: A dictionary with keys 'function', 'region', 'generation', 'project'.
    """
    # Define the regex patterns for Cloud Run and Cloud Functions URLs
    cloud_run_pattern = re.compile(r'https:\/\/console\.cloud\.google\.com\/run\/detail\/(?P<region>[^\/]+)\/(?P<function>[^\/]+)\/revisions\?project=(?P<project>[^\/]+)')
    cloud_functions_pattern = re.compile(r'https:\/\/console\.cloud\.google\.com\/functions\/details\/(?P<region>[^\/]+)\/(?P<function>[^\/]+)\?project=(?P<project>[^\/]+)')

    # Match the URL against the patterns
    match = cloud_run_pattern.match(url)
    if match:
        return {
            'function': match.group('function'),
            'region': match.group('region'),
            'generation': 2,
            'project': match.group('project')
        }

    match = cloud_functions_pattern.match(url)
    if match:
        return {
            'function': match.group('function'),
            'region': match.group('region'),
            'generation': 1,
            'project': match.group('project')
        }

    # If the URL doesn't match any pattern, return None
    logger.error(f"Invalid GCP URL: {url}")
    return None

def remediate(context):
    """
    Remediate the specified Google Cloud Run service to remove public access.
    
    Args:
        context (dict): Contextual information including project ID, function name, and region.
    """
    try:
        logger.info(f"This playbook is invoked by {context['ps_queue']}")
        gcp_function = parse_gcp_url(context['metadata']['cloudProviderURL'])

        if not gcp_function:
            logger.error("Failed to parse GCP URL from context")
            return
        
        # Print the extracted information for verification
        logger.info(f"Project ID: {gcp_function['project']}")
        logger.info(f"Function Name: {gcp_function['function']}")
        logger.info(f"Region: {gcp_function['region']}")
            
        # Remove public access by calling the appropriate remove_public_access function
        if gcp_function['generation'] == 2:
            logger.info("Generation 2")
    
            # Initialize the client for Google Cloud Run
            client = run_v2.ServicesClient()
    
            # Construct the full resource name for the Cloud Run service
            resource_name = f"projects/{gcp_function['project']}/locations/{gcp_function['region']}/services/{gcp_function['function']}"
    
            success = remove_public_access_gen2(client, resource_name)
        else:
            logger.info("Generation 1")
    
            # Initialize the client for Google Cloud Functions
            client = functions_v1.CloudFunctionsServiceClient()
    
            # Construct the full resource name for the Cloud Function
            resource_name = f"projects/{gcp_function['project']}/locations/{gcp_function['region']}/functions/{gcp_function['function']}"
    
            success = remove_public_access_v1(client, resource_name)
    
        if success:
            logger.info("Public access successfully removed.")
        else:
            logger.info("No public access roles found or already removed.")
    except Exception as e:
        logger.error(f"An error occurred during remediation: {e}")