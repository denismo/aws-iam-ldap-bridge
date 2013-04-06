Introduction
============

This project contains AWS IAM bridge for ApacheDS 2.0.0-M11. It is designed to be used
straight away on any Linux system which has Java 6 without any manual configuration. For example, it can be embedded into
an AWS AMI and used for all your servers to allow the AWS IAM authentication of Linux users.

The bridge periodically populates the LDAP directory location with the users, groups and roles from AWS IAM. If you configure
you Linux with LDAP authentication (for example, using libpam-ldapd) it will allow authentication of the Linux users against
AWS IAM using their AWS IAM Secret Keys as passwords.

After login, the user will have the Linux groups corresponding to the IAM groups that were assigned to them.

Note: The user's AWS Secret Keys are never stored in any persistent storage or logs.

For more information, please read the `INSTALL`_ document inside of the installation package.

Note: There is a bug in ApacheDS 2.0.0-M11 which prevents custom authenticators from running. The installation package
for this project provides a patched package of ApahacheDS 2.0.0-M11.

.. _INSTALL: https://bitbucket.org/denismo/iam4apacheds/src/6f544c8bd80886a0c02315dc980f23a2cf0761a7/dist/apacheds/INSTALL?at=master