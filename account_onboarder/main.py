import fnmatch
import logging
import os
import sys
from enum import Enum

import boto3
import colored
import requests
import typer
import yaml
from colored import stylize

# Set up our logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Secret variables, bring them in from environment
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
SNYK_TOKEN = os.getenv("SNYK_TOKEN")

# Constants
BASE_URL = "https://api.snyk.io/"
HEADERS = {"Authorization": f"token {SNYK_TOKEN}"}
API_VERSION = "2023-01-04~beta"
ROLE_ARN_TEMPLATE = "arn:aws:iam::{}:role/{}"
STACK_NAME_TEMPLATE = "SnykCloudOnboarding-{}"

# Constants for coloured output
STYLE_INFO = colored.fg("blue") + colored.attr("bold")
STYLE_ERR = colored.fg("red") + colored.attr("bold")
STYLE_WARN = colored.fg("yellow") + colored.attr("bold")
STYLE_SUCCESS = colored.fg("green") + colored.attr("bold")


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
    def get_onboarded_account_ids(self, org_id):
        """
        Queries the Snyk API to get a list of Cloud environments
        that have already been onboarded into Snyk Cloud.
        :param org_id: the org ID in Snyk
        :return: List of onboarded accounts
        """
        onboarded_environments = []
        logger.debug(
            f"Querying Snyk Cloud for existing onboarded AWS Accounts within {org_id}"
        )

        # Do the first page of results
        response = requests.get(
            f"{BASE_URL}/rest/orgs/{org_id}/cloud/environments?version={API_VERSION}&kind=aws&limit=100",
            headers=HEADERS,
        )
        onboarded_environments.extend(
            [x["attributes"]["native_id"] for x in response.json()["data"]]
        )

        # Go through all the pages until we're done
        while response.json().get("links", {}).get("next"):
            response = requests.get(
                f"{BASE_URL}{response.json()['links'].get('next')}", headers=HEADERS
            )
            onboarded_environments.extend(
                [x["attributes"]["native_id"] for x in response.json()["data"]]
            )
        return onboarded_environments

    def generate_snyk_cloud_aws_cfn_template(self, org_id):
        """
        Makes a request to the Snyk API to generate a CFN template for deployment to our AWS environment
        :param org_id: the org ID
        :return: The CloudFormation template in YAML format
        """
        response = requests.post(
            f"{BASE_URL}rest/orgs/{org_id}/cloud/permissions?version={API_VERSION}",
            headers=HEADERS,
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
            headers=HEADERS,
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
        client = _get_session().client("sts")
        response = client.assume_role(**args)
        return boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )

    def get_accounts_in_organization(self):
        """
        Gets a list of ACTIVE accounts within the current AWS organization
        :return: the list of accounts
        """
        client = _get_session().client("organizations")
        paginator = client.get_paginator("list_accounts")
        accounts = []
        response_iterator = paginator.paginate()
        for page in response_iterator:
            accounts.extend(page.get("Accounts"))
        return [
            x for x in accounts if x.get("Status") == "ACTIVE"
        ]  # No point getting inactive accounts


def _get_session():
    return boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def _load_config(config_file):
    """
    Loads the specified yaml file
    :param config_file: the file path
    :return: Loaded config
    """
    with open(config_file, "r") as fs:
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


def main(
    config_file: str = "config.yaml",
    debug: bool = False,
    ignore_existing: bool = False,
    no_dry_run: bool = False,
):
    # Print log to stdout and set level to debug if the user asks for it
    if debug:
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Instantiate the helper classes
    aws = AwsUtilities()
    snyk = SnykUtilities()

    # Load our config file and parse it
    config = _load_config(config_file)
    mapping_rules = _prepare_mapping_rules(config["account_org_mapping_rules"])
    print(stylize("Config file successfully loaded...", STYLE_SUCCESS))

    # Pull down a list of accounts and then filter them based on our rules
    print("Attempting to grab list of accounts from AWS...")
    master_account_list = aws.get_accounts_in_organization()
    print(stylize(f"Found {len(master_account_list)} accounts...", STYLE_SUCCESS))

    # Go through each account and set it up in Snyk, then deploy the cfn template
    for account in master_account_list:
        print(stylize(f"[{account['Id']}] ", STYLE_INFO) + "Processing account")
        match_found, matched_rule = _test_subject(account, mapping_rules)

        # No need to process further if no match is found
        if not match_found:
            print(
                stylize(f"[{account['Id']}] ", STYLE_INFO)
                + stylize(
                    f"Warning: No match found for account {account['Id']} - you may need to update your filter rules",
                    STYLE_WARN,
                )
            )
            continue
        else:
            existing_environments = snyk.get_onboarded_account_ids(matched_rule.org_id)

            # If there's a Snyk Cloud environment for this account already, skip it
            if account["Id"] in existing_environments and not ignore_existing:
                print(
                    stylize(f"[{account['Id']}] ", STYLE_INFO)
                    + stylize(
                        f"Error: Account already onboarded to Snyk Cloud (run with --ignore-existing to override)",
                        STYLE_ERR,
                    )
                )
            else:
                print(
                    stylize(f"[{account['Id']}] ", STYLE_INFO)
                    + stylize(
                        f"Found match - mapped to org {matched_rule.org_id}",
                        STYLE_SUCCESS,
                    )
                )
                if no_dry_run:
                    # Create a cloudformation template to deploy in to this account
                    template = snyk.generate_snyk_cloud_aws_cfn_template(
                        matched_rule.org_id
                    )

                    # Assume a role in to the target account and deploy the cfn template
                    stack_name = STACK_NAME_TEMPLATE.format(account["Id"])
                    if account["Id"] == config["organizations_master_account_id"]:
                        print(
                            stylize(f"[{account['Id']}] ", STYLE_INFO)
                            + stylize(
                                "Deploying in master account, skipping role assumption...",
                                STYLE_WARN,
                            )
                        )
                        assumed_session = _get_session()
                    else:
                        assumed_session = aws.role_arn_to_session(
                            RoleArn=ROLE_ARN_TEMPLATE.format(
                                account["Id"], config["account_access_role"]
                            ),
                            RoleSessionName="SnykCloudDeploymentSession",
                        )
                        print(
                            stylize(f"[{account['Id']}] ", STYLE_INFO)
                            + f"Assumed role in target account {account['Id']}"
                        )
                    assumed_cfn_client = assumed_session.client(
                        "cloudformation", region_name=config.get("deployment_region")
                    )
                    assumed_cfn_client.create_stack(
                        StackName=stack_name,
                        Parameters=[],
                        TemplateBody=template,
                        Capabilities=["CAPABILITY_NAMED_IAM"],
                    )
                    print(
                        stylize(f"[{account['Id']}] ", STYLE_INFO)
                        + f"Created stack {stack_name} in account {account['Id']} - waiting for completion..."
                    )

                    # Wait for the template to finish deploying
                    assumed_cfn_client.get_waiter("stack_create_complete").wait(
                        StackName=stack_name
                    )

                    # Get the role arn from the stack outputs
                    print(
                        stylize(f"[{account['Id']}] ", STYLE_INFO)
                        + stylize(f"Stack creation finished...", STYLE_SUCCESS)
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
                    print(
                        stylize(f"[{account['Id']}] ", STYLE_INFO)
                        + f"Found Snyk role {snyk_cloud_role_arn} in stack outputs, deploying Snyk Cloud environment..."
                    )
                    if snyk_cloud_role_arn:
                        snyk.create_snyk_cloud_environment(
                            matched_rule.org_id, snyk_cloud_role_arn
                        )
                        print(
                            stylize(f"[{account['Id']}] ", STYLE_INFO)
                            + stylize(f"...done", STYLE_SUCCESS)
                        )

    # If we're running in dry run mode, then we should tell the user to run the no dry run in order to do it
    if not no_dry_run:
        print(
            stylize(
                f"Please re-run with --no-dry-run to continue creating Snyk Cloud environments",
                STYLE_WARN,
            )
        )


if __name__ == "__main__":
    typer.run(main)
