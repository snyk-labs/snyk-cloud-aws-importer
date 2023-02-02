# Snyk Cloud - AWS account monitor
This project provides a CloudFormation template which deploys EventBridge rules to hook on to both Control Tower lifecycle events and Organizations account creation events. These events are then fed in to a Lambda function which will automate the process of onboarding this account in to Snyk Cloud.

## Pre-requsites
* Access to your AWS organizational master account to deploy the CloudFormation template

## Deploying the CloudFormation template
######

### Setting up your configuration
The config (in JSON format) tells the tool some basic information about your AWS setup (things like regions, roles, etc) and
also contains the rules the tool will use to map AWS accounts to Snyk organisations. Below is a reference for the config
file which details what each parameter is for and what values it can be set to. This config is stored in SSM as a JSON
document which the Lambda function uses. 

* *deployment_region*: The region where the tool should deploy the CloudFormation template (the template only deploys
a role, so this region doesn't impact anything material see: [AWS Global Services](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/#:~:text=Except%20as%20otherwise%20specified%2C%20Global,store%20and%20process%20data%20globally.))
* *account_org_mapping_rules*: A list of rules which tell the tool which Snyk organisation your AWS environment should be added
* *account_org_mapping_rules.[].org_id*: The Snyk org ID where an AWS environment will be put if it matches this rule
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

### Building AWS Lambda Package
Before the CloudFormation template can be deployed, we must build the Lambda package so that it can be deployed to AWS. To do this ensure the `build_lambda.sh` file ie executable:

```bash
chmod u+x build_lambda.sh
```

Once the file is executable, you can build the Lambda package simply by running the following command:

```bash
./build_lambda.sh
```

This will create a new file in your current working directory called `aws-account-monitor.zip`. This file can now be uploaded to a public S3 bucket or if you prefer to host this in a private bucket.