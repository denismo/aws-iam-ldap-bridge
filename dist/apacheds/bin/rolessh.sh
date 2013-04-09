#!/bin/bash

role=`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null`
keys=`curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$role/ 2>/dev/null`
token=`echo $keys | jq -r .Token`
accessKey=`echo $keys | jq -r .AccessKeyId`
secretKey=`echo $keys | jq -r .SecretAccessKey`

expect rolessh.exp $1 $role "$accessKey|$secretKey|$token" "$2"
