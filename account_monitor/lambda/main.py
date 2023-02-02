#
# © 2023 Snyk Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import fnmatch
import json
import logging
import os
import json
from enum import Enum

import boto3
import requests

# Set up our logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Constants
CT_EVENT_ORGANIZATIONS = "CreateAccountResult"
CT_EVENT_CONTROLTOWER = "CreateManagedAccount"
SECRET_SNYK_ACCOUNT_MONITOR = os.getenv("SNYK_TOKEN_SECRET")
ROLE_ARN_TEMPLATE = "arn:aws:iam::{}:role/{}"
BASE_URL = "https://api.snyk.io/"
API_VERSION = "2023-01-04~beta"
STACK_NAME_TEMPLATE = "SnykCloudOnboarding-{}"
SSM_CONFIG_NAME = os.getenv("SSM_CONFIG_NAME")


class FilterMatchResult(Enum):
    MATCH = 1
    NO_MATCH = 2
    NOT_APPLICABLE = 3


class MappingMatchType(Enum):
    ANY = 4
    ALL = 5
    DEFAULT = 6


class AccountFilter:
    def __init__(self, account_ids=[], email_patterns=[], name_patterns=[]):
        self.account_ids = account_ids
        self.email_patterns = email_patterns
        self.name_patterns = name_patterns

    def account_id_match(self, subject):
        """
        Will check if any of the account IDS specified in the filter match the subject
        :param subject: the account we're checking
        :return: MATCH if a match is found, NO_MATCH otherwise or NOT_APPLICABLE if no account IDS specified
        """
        logger.debug(f"account_id_match [subject={subject}]")
        if len(self.account_ids) == 0:
            logger.debug(f"no account ids specified so returning NOT_APPLICABLE")
            return FilterMatchResult.NOT_APPLICABLE
        return (
            FilterMatchResult.MATCH
            if subject.get("Id") in self.account_ids
            else FilterMatchResult.NO_MATCH
        )

    def email_match(self, subject):
        """
        Will check if any of the emails specified in the filter match the subject
        :param subject: the account we're checking
        :return: MATCH if a match is found, NO_MATCH otherwise or NOT_APPLICABLE if no emails specified
        """
        logger.debug(f"email_match [subject={subject}]")
        if len(self.email_patterns) == 0:
            logger.debug(f"no emails specified so returning NOT_APPLICABLE")
            return FilterMatchResult.NOT_APPLICABLE
        for pattern in self.email_patterns:
            logger.debug("Testing email pattern {}".format(pattern))
            if fnmatch.fnmatch(subject.get("Email"), pattern):
                return FilterMatchResult.MATCH
        return FilterMatchResult.NO_MATCH

    def name_match(self, subject):
        """
        Will check if any of the account names specified in the filter match the subject
        :param subject: the account we're checking
        :return: MATCH if a match is found, NO_MATCH otherwise or NOT_APPLICABLE if no account names specified
        """
        logger.debug(f"name_match [subject={subject}]")
        if len(self.name_patterns) == 0:
            logger.debug(f"no names specified so returning NOT_APPLICABLE")
            return FilterMatchResult.NOT_APPLICABLE
        for pattern in self.name_patterns:
            if fnmatch.fnmatch(subject.get("Name"), pattern):
                return FilterMatchResult.MATCH
        return FilterMatchResult.NO_MATCH


class MappingRule:
    def __init__(self, filter, org_id, match_type):
        self.filter = filter
        self.org_id = org_id
        self.match_type = match_type

    def is_match(self, subject):
        """
        Checks the filter rules based on the match type to see if a match was found
        :param subject: the account we're checking
        :return: True if a match was found, False otherwise
        """
        # If it's default, just return true
        if self.match_type == MappingMatchType.DEFAULT:
            return True

        id_result = self.filter.account_id_match(subject)
        email_result = self.filter.email_match(subject)
        name_result = self.filter.name_match(subject)

        if self.match_type == MappingMatchType.ALL:
            return (
                id_result != FilterMatchResult.NO_MATCH
                and email_result != FilterMatchResult.NO_MATCH
                and name_result != FilterMatchResult.NO_MATCH
            )
        elif self.match_type == MappingMatchType.ANY:
            return (
                id_result == FilterMatchResult.MATCH
                or email_result == FilterMatchResult.MATCH
                or name_result == FilterMatchResult.MATCH
            )


class SnykUtilities:
    def __init__(self, snyk_token):
        self.snyk_token = snyk_token
        self.headers = {"Authorization": f"token {self.snyk_token}"}

    def generate_snyk_cloud_aws_cfn_template(self, org_id):
        """
        Makes a request to the Snyk API to generate a CFN template for deployment to our AWS environment
        :param org_id: the org ID
        :return: The CloudFormation template in YAML format
        """
        response = requests.post(
            f"{BASE_URL}rest/orgs/{org_id}/cloud/permissions?version={API_VERSION}",
            headers=self.headers,
            json={
                "data": {
                    "attributes": {"platform": "aws", "type": "cf"},
                    "type": "permission",
                }
            },
        )
        return response.json()["data"]["attributes"]["data"]

    def create_snyk_cloud_environment(self, org_id, role_arn):
        """
        Creates a Snyk Cloud environment
        :param org_id: the org ID to create the envionment within
        :param role_arn: the role arn that was deployed by the script
        :return: True if the status code was 201 (success) False otherwise
        """
        logger.debug(f"creating snyk cloud env with {org_id} and {role_arn}")
        response = requests.post(
            f"{BASE_URL}rest/orgs/{org_id}/cloud/environments?version={API_VERSION}",
            headers=self.headers,
            json={
                "data": {
                    "attributes": {"kind": "aws", "options": {"role_arn": role_arn}},
                    "type": "environment",
                }
            },
        )
        logger.debug(response.status_code)
        logger.debug(response.content)
        return response.status_code == 201


class AwsUtilities:
    def role_arn_to_session(self, **args):
        """
        Assumes a role in a target account
        :param args: args
        :return: A session
        """
        client = boto3.client("sts")
        response = client.assume_role(**args)
        return boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )

    def describe_account(self, account_id):
        client = boto3.client("organizations")
        response = client.describe_account(AccountId=account_id)
        return response["Account"]


def get_snyk_token_secret():
    """
    Grabs the Snyk token from Secrets Maneger
    :return:
    """
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=SECRET_SNYK_ACCOUNT_MONITOR)
    secret_value = response["SecretString"]
    token = json.loads(secret_value)["token"]
    return token


def get_account_monitor_config():
    client = boto3.client("ssm")
    response = client.get_parameter(
        Name=SSM_CONFIG_NAME,
        WithDecryption=True | False
    )
    return response["Parameter"]["Value"]


def _load_config():
    """
    Loads the specified yaml file
    :param config_file: the file path
    :return: Loaded config
    """
    config_str = get_account_monitor_config()
    return json.loads(config_str)


def _prepare_mapping_rules(mapping_rules):
    """
    Parses the mapping rules from the yaml format to objects we can work with
    :param mapping_rules: the yaml format rules
    :return: A list of mapping rule objects
    """
    loaded_mapping_rules = []
    for rule in mapping_rules:
        match_type = MappingMatchType[rule["match_type"]]
        if match_type == MappingMatchType.DEFAULT:
            filter = None
        else:
            filter = AccountFilter(
                rule["filter"].get("account_ids", []),
                rule["filter"].get("email_patterns", []),
                rule["filter"].get("name_patterns", []),
            )
        mapping = MappingRule(filter, rule["org_id"], match_type)
        loaded_mapping_rules.append(mapping)
    logger.debug(f"loaded {len(loaded_mapping_rules)} mapping rules from config")
    return loaded_mapping_rules


def _test_subject(subject, mapping_rules):
    """
    Tests a given account against the list of mapping rules we have, if a match is found we return True and the matched
    rule in question
    :param subject: the account we're testing
    :param mapping_rules: the list of all mapping rules
    :return: True if a match was found, False otherwise
    """
    logger.debug(
        f"testing subject against {len(mapping_rules)} mapping rules [subject={subject}]"
    )
    for rule in mapping_rules:
        if rule.is_match(subject):
            logger.debug("found match")
            return True, rule
    logger.debug("no match found")
    return False, None


def lambda_handler(event, context):
    # Instantiate the helpers
    snyk = SnykUtilities(get_snyk_token_secret())
    aws = AwsUtilities()

    # Load config and mapping rules
    config = _load_config()
    mapping_rules = _prepare_mapping_rules(config["account_org_mapping_rules"])

    # Find which default role to use based on the type of event we receive
    if event["detail"]["eventName"] == CT_EVENT_CONTROLTOWER:
        logger.info("Detected ControlTower event source")
        role = "AWSControlTowerExecution"
        account_id = event["detail"]["serviceEventDetails"][
            "createManagedAccountStatus"
        ]["account"]["accountId"]
    elif event["detail"]["eventName"] == CT_EVENT_ORGANIZATIONS:
        logger.info("Detected Organizations event source")
        role = "OrganizationAccountAccessRole"
        account_id = event["detail"]["serviceEventDetails"]["createAccountStatus"][
            "accountId"
        ]
    account_details = aws.describe_account(account_id)

    # Let's see if we can find a match for the created account
    match_found, matched_rule = _test_subject(account_details, mapping_rules)

    if match_found:
        # Now assume that role and get a session in to the remote account
        logger.info("Assuming role {} in account {}".format(role, account_id))
        assumed_session = aws.role_arn_to_session(
            RoleArn=ROLE_ARN_TEMPLATE.format(account_id, role),
            RoleSessionName="SnykCloudDeploymentSession",
        )

        # Create a cloudformation template to deploy in to this account
        logger.info("Generating Snyk Cloud deployment template")
        template = snyk.generate_snyk_cloud_aws_cfn_template(matched_rule.org_id)

        # Assume a role in to the target account and deploy the cfn template
        stack_name = STACK_NAME_TEMPLATE.format(account_id)
        logger.info(f"Deploying {stack_name} in {account_id}")
        assumed_cfn_client = assumed_session.client(
            "cloudformation", region_name=config.get("deployment_region")
        )
        assumed_cfn_client.create_stack(
            StackName=stack_name,
            Parameters=[],
            TemplateBody=template,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )

        # Wait for the template to finish deploying
        logger.info("Waiting for stack create completion...")
        assumed_cfn_client.get_waiter("stack_create_complete").wait(
            StackName=stack_name
        )

        response = assumed_cfn_client.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0]["Outputs"]

        # Get the variable from the stack outputs
        snyk_cloud_role_arn = None
        for output in outputs:
            if output["OutputKey"] == "SnykCloudRoleArn":
                snyk_cloud_role_arn = output["OutputValue"]
                break

        # Now create the environment based on that role arn
        if snyk_cloud_role_arn:
            logger.info("Creating Snyk Cloud environment...")
            snyk.create_snyk_cloud_environment(matched_rule.org_id, snyk_cloud_role_arn)
            logger.info("..done")
    else:
        logger.warning(f"No match found for account {account_id}")
