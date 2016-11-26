#!/bin/bash
SRC_DIR=`dirname $0`/..
source $SRC_DIR/version
aws s3 cp target/apacheds-$release.zip s3://aws-iam-apacheds/ --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers