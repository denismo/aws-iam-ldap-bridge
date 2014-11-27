[![Build Status](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/badge/icon)](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/)

Introduction
============

This project contains AWS IAM bridge for ApacheDS 2.0.0-M17. It is designed to be used
straight away on any Linux system which has Java 6 without any manual configuration. For example, it can be embedded into
an AWS AMI and used for all your servers to allow the AWS IAM authentication of Linux users.

The bridge periodically populates the LDAP directory location with the users, groups and roles from AWS IAM. If you configure
you Linux with LDAP authentication (for example, using libpam-ldapd) it will allow authentication of the Linux users against
AWS IAM using their AWS IAM Secret Keys or AWS IAM passwords.

After login, the user will have the Linux groups corresponding to the IAM groups that were assigned to them.

Note: The user's AWS Secret Keys are never stored in any persistent storage or logs.

For more information, please read the [INSTALL](INSTALL.md) document inside of the installation package.

