#!/bin/bash

role=`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
keys=`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$role/`
token=`echo $keys | jq -r .Token`
accessKey=`echo $keys | jq -r .AccessKeyId`
secretKey=`echo $keys | jq -r .SecretAccessKey`

expect rolessh.exp $1 $role "$accessKey|$secretKey|$token" "$2"
