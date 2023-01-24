import boto3
import os
import re
import requests
import typer
import yaml
import logging
import sys

from enum import Enum

# Set up our logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Temp: Print to stdout
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Secret variables, bring them in from environment
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
SNYK_TOKEN = os.getenv("SNYK_TOKEN")

# Constants
BASE_URL = "https://api.snyk.io/rest/"
HEADERS = {"Authorization": f"token {SNYK_TOKEN}"}
API_VERSION = "2023-01-04~beta"
ROLE_ARN_TEMPLATE = "arn:aws:iam::{}:role/OrganizationAccountAccessRole"
STACK_NAME_TEMPLATE = "SnykCloudOnboarding-{}"


class FilterMatchResult(Enum):
    MATCH = 1
    NO_MATCH = 2
    NOT_APPLICABLE = 3


class MappingMatchType(Enum):
    ANY = 4
    ALL = 5
    DEFAULT = 6


class AccountFilter:
    def __init__(self,  account_ids=[], email_regexes=[], name_regexes=[]):
        self.account_ids = account_ids
        self.email_regexes = email_regexes
        self.name_regexes = name_regexes

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
        return FilterMatchResult.MATCH if subject.get("Id") in self.account_ids else FilterMatchResult.NO_MATCH

    def email_match(self, subject):
        """
        Will check if any of the emails specified in the filter match the subject
        :param subject: the account we're checking
        :return: MATCH if a match is found, NO_MATCH otherwise or NOT_APPLICABLE if no emails specified
        """
        logger.debug(f"email_match [subject={subject}]")
        if len(self.email_regexes) == 0:
            logger.debug(f"no emails specified so returning NOT_APPLICABLE")
            return FilterMatchResult.NOT_APPLICABLE
        for pattern in self.email_regexes:
            if re.match(pattern, subject.get("Email")):
                return FilterMatchResult.MATCH
        return FilterMatchResult.NO_MATCH

    def name_match(self, subject):
        """
        Will check if any of the account names specified in the filter match the subject
        :param subject: the account we're checking
        :return: MATCH if a match is found, NO_MATCH otherwise or NOT_APPLICABLE if no account names specified
        """
        logger.debug(f"name_match [subject={subject}]")
        if len(self.name_regexes) == 0:
            logger.debug(f"no names specified so returning NOT_APPLICABLE")
            return FilterMatchResult.NOT_APPLICABLE
        for pattern in self.name_regexes:
            if re.match(pattern, subject.get("Name")):
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
            return id_result != FilterMatchResult.NO_MATCH and email_result != FilterMatchResult.NO_MATCH \
                and name_result != FilterMatchResult.NO_MATCH
        elif self.match_type == MappingMatchType.ANY:
            return id_result == FilterMatchResult.MATCH or email_result == FilterMatchResult.MATCH \
                or name_result == FilterMatchResult.MATCH


class SnykUtilities:

    def generate_snyk_cloud_aws_cfn_template(self, org_id):
        """
        Makes a request to the Snyk API to generate a CFN template for deployment to our AWS environment
        :param org_id: the org ID
        :return: The CloudFormation template in YAML format
        """
        response = requests.post(
            f"{BASE_URL}orgs/{org_id}/cloud/permissions?version={API_VERSION}",
            headers=HEADERS,
            json={
              "data": {
                "attributes": {
                  "platform": "aws",
                  "type": "cf"
                },
                "type": "permission"
              }
            }
        )
        return response.json()["data"]["attributes"]["data"]

    def create_snyk_cloud_environment(self, org_id, role_arn):
        """
        Creates a Snyk Cloud environment
        :param org_id: the org ID to create the envionment within
        :param role_arn: the role arn that was deployed by the script
        :return: True if the status code was 201 (success) False otherwise
        """
        response = requests.post(
            f"{BASE_URL}orgs/{org_id}/cloud/permissions?version={API_VERSION}",
            headers=HEADERS,
            json={
              "data": {
                "attributes": {
                  "kind": "aws",
                  "options": {
                    "role_arn": role_arn
                  }
                },
                "type": "environment"
              }
            }
        )
        return response.status_code == 201

class AwsUtilities:
    def role_arn_to_session(self, **args):
        """
        Assumes a role in a target account
        :param args: args
        :return: A session
        """
        client = self.get_session().client('sts')
        response = client.assume_role(**args)
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])

    def get_session(self):
        return boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )

    def get_accounts_in_organization(self):
        """
        Gets a list of ACTIVE accounts within the current AWS organization
        :return: the list of accounts
        """
        client = self.get_session().client("organizations")
        paginator = client.get_paginator('list_accounts')
        accounts = []
        response_iterator = paginator.paginate()
        for page in response_iterator:
            accounts.extend(page.get('Accounts'))
        return [x for x in accounts if x.get("Status") == "ACTIVE"]  # No point getting inactive accounts


def _load_config(config_file):
    """
    Loads the specified yaml file
    :param config_file: the file path
    :return: Loaded config
    """
    with open(config_file, 'r') as fs:
        return yaml.safe_load(fs)


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
            filter = AccountFilter(rule["filter"].get("account_ids", []), rule["filter"].get("email_regexes", []),
                                   rule["filter"].get("name_regexes", []))
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
    logger.debug(f"testing subject against {len(mapping_rules)} mapping rules [subject={subject}]")
    for rule in mapping_rules:
        if rule.is_match(subject):
            logger.debug("found match")
            return True, rule
    logger.debug("no match found")
    return False, None


def main(config_file : str = "config.yaml"):
    # Instantiate the helper classes
    aws = AwsUtilities()
    snyk = SnykUtilities()

    # Load our config file and parse it
    logger.info("loading config...")
    config = _load_config(config_file)
    mapping_rules = _prepare_mapping_rules(config["account_org_mapping_rules"])

    # Pull down a list of accounts and then filter them based on our rules
    master_account_list = aws.get_accounts_in_organization()

    # Go through each account and set it up in Snyk, then deploy the cfn template
    for account in master_account_list:
        match_found, matched_rule = _test_subject(account, mapping_rules)

        # No need to process further if no match is found
        if not match_found:
            continue

        # Create a cloudformation template to deploy in to this account
        template = snyk.generate_snyk_cloud_aws_cfn_template(matched_rule.org_id)

        # Assume a role in to the target account and deploy the cfn template
        stack_name = STACK_NAME_TEMPLATE.format(account["Id"])
        assumed_session = aws.role_arn_to_session(
            RoleArn=ROLE_ARN_TEMPLATE.format(account["Id"]),
            RoleSessionName="SnykCloudDeploymentSession")
        assumed_cfn_client = assumed_session.client("cloudformation", region_name=config.get("deployment_region"))
        assumed_cfn_client.create_stack(
            StackName=stack_name,
            Parameters=[],
            TemplateBody=template,
            Capabilities=['CAPABILITY_NAMED_IAM']
        )

        # Wait for the template to finish deploying
        assumed_cfn_client.get_waiter('stack_create_complete').wait(StackName=stack_name)

        # Get the role arn from the stack outputs
        response = assumed_cfn_client.describe_stacks(StackName=stack_name)
        outputs = response['Stacks'][0]['Outputs']

        # Get the variable from the stack outputs
        snyk_cloud_role_arn = None
        for output in outputs:
            if output['OutputKey'] == "SnykCloudRoleArn":
                snyk_cloud_role_arn = output['OutputValue']
                break

        # Now create the environment based on that role arn
        if snyk_cloud_role_arn:
            snyk.create_snyk_cloud_environment(matched_rule.org_id, snyk_cloud_role_arn)


if __name__ == "__main__":
    typer.run(main)