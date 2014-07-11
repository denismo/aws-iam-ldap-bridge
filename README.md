[![Build Status](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/badge/icon)](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/)

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

For more information, please read the [INSTALL](INSTALL.md) document inside of the installation package.

Support
=======

Please donate to support the development and bug fixing of this project.

<form action="https://www.paypal.com/cgi-bin/webscr" method="post" target="_top">
<input type="hidden" name="cmd" value="_s-xclick">
<input type="hidden" name="encrypted" value="-----BEGIN PKCS7-----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-----END PKCS7-----
">
<input type="image" src="https://www.paypalobjects.com/en_AU/i/btn/btn_donate_LG.gif" border="0" name="submit" alt="PayPal — The safer, easier way to pay online.">
<img alt="" border="0" src="https://www.paypalobjects.com/en_AU/i/scr/pixel.gif" width="1" height="1">
</form>


