# Snyk Cloud - AWS Deployment Tool

This tool allows you to deploy Snyk Cloud across an AWS Organization in an automated way. It integrates directly with
AWS Organizations to find out the accounts we should deploy Snyk Cloud to, it'll generate the CloudFormation template
which is required by Snyk Cloud (the IAM role we assume), deploy that template and finally add the environment in to
Snyk. It also allows you to filter based on account attributes and based on these filters, you can decide which Snyk
organisation to place this AWS environment in.

## Pre-requsites
* Python3 & Poetry installed on the machine where the script will run
* Access to your AWS organizational master account (via access keys)

## Quick start
### Install Python requiements
```bash
poetry shell
poetry install
```

### Setting up your config.yaml file
The `config.yaml` file tells the tool some basic information about your AWS setup (things like regions, roles, etc) and
also contains the rules the tool will use to map AWS accounts to Snyk organisations. Below is a reference for the config
file which details what each parameter is for and what values it can be set to. All parameters are required unless
stated as optional.

* *account_access_role*: The role which can be assumed **from** the master account in to child accounts. By default 
AWS set this to `OrganizationAccountAccessRole`, but it may vary.
* *organizations_master_account_id*: The AWS organizational master account ID (string format!!)
* *deployment_region*: The region where the tool should deploy the CloudFormation template (the template only deploys
a role, so this region doesn't impact anything material see: [AWS Global Services](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/#:~:text=Except%20as%20otherwise%20specified%2C%20Global,store%20and%20process%20data%20globally.))
* *snyk_group_id*: The group where we'll create new accounts (if using org_name)
* *account_org_mapping_rules*: A list of rules which tell the tool which Snyk organisation your AWS environment should be added
* *account_org_mapping_rules.[].org_id (Optional)*: The Snyk org ID where an AWS environment will be put if it matches this rule (use this OR org_name)
* *account_org_mapping_rules.[].org_name (Optional)*: The Snyk org name where an AWS environment will be put if it matches this rule (use this OR org_id)
* *account_org_mapping_rules.[].match_type*: How we'll match the filters in this rule. Can be set to `ALL`, `ANY` or 
`DEFAULT`. ALL means that all filters must match for the rule to be applied, ANY means only one filter must match for
the rule to be applied and DEFAULT needs no `filter` section, this rule should come **at the end** and will be applied
without any matching.
* *account_org_mapping_rules.[].filter*: A map (dictionary) defining the filters
* *account_org_mapping_rules.[].filter.account_ids*: A list of account IDs to check against
* *account_org_mapping_rules.[].filter.email_patterns* A list of patterns to match against (accepts wildcards). These patterns will be tested against
the email address of the AWS account
* *account_org_mapping_rules.[].filter.name_patterns*: A list of patterns to match against (accepts wildcards). These patterns will be tested against
the friendly name of the AWS account

A sample config file which makes use of all available configuration options can be seen in `config.yaml.example`

### Ensure your environment is set up
You will need:
* AWS credentials (access key id and secret access key)
* A Snyk API token

```bash
export SNYK_TOKEN=...
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

### Run the tool (Dry Run Mode)
The default behaviour of the script is to run in dry run mode. This will print the AWS accounts that are detected and which Snyk orgs they would be mapped to. When you are ready to start onboarding Snyk Cloud Environments, append `--no-dry-run`. See below for examples.

```bash
python main.py --config-file config.yaml
```

### Run the tool (Live)
```bash
python main.py --config-file config.yaml --no-dry-run
```

### Running in an EC2 instance
By default, if the script is running in an EC2 instance, it'll try and grab temporary credentials and use the instance profile assigned to the instance. If you wish to turn off this behaviour and provide your own credentials, then use the `--use-instance-metadata=false` flag. The script will then revert to using provided credentials.
### Check results
In Snyk:
* Click on the settings icon for your organisation
* Click "Cloud Environments" in the left hand menu bar
* Check to ensure the cloud environments you were expecting to be imported, have been. These will also show as "Scanning".