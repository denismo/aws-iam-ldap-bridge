[![Build Status](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/badge/icon)](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/)

Introduction
============

This project provides an implementation of Unix PAM authentication using AWS IAM ("Identity and Access Management").
It removes the need for everyone to login using shared certificates, or maintain copy of all certificates on all instances
for all the users of your team (and operations, and support etc.).
It also simplifies the scripted authenticated access from one machine to another via IAM Role-based logins (highly experimental).

It works by integrating into ApacheDS LDAP server as a plugin. The plugin periodically populates the LDAP directory location with the
users and groups from AWS IAM. When Linux PAM is configured with LDAP authentication this allows for authenticating the Linux users against
these replicated AWS IAM users which effectively as if you authenticated against AWS IAM directly.

The authentication works based on using the AWS IAM user name as Linux account name, and (the first) Secret Key as password.
After login, the users will have the Linux groups corresponding to the IAM groups that were assigned to them. All accounts (users and groups) are
created and updated automatically. If the user does not have access key/secret key the account is not created in LDAP.

> *Note:* The user's AWS Secret Keys are never stored in any persistent storage or logs. Only user names and accessKeys are stored in LDAP, and
those are filtered out of search results if `ads-dspasswordhidden` property is set.

By default, the users are cached in LDAP at ou=users,dc=iam,dc=aws,dc=org and groups as ou=groups,dc=iam,dc=aws,dc=org. You can change
that by modifying the rootDN in the config file (see below) before starting the server.

> _You should also be aware that this project is in its early stages. No formal security assessment has been done against it. Considering that,
you are NOT advised to use it for any security sensitive application. Feel free to evaluate this project but be aware that you use it at your own risk._

Quick start from AMI (NEW)
====================

The software is now available as a pre-built AMI (based on Amazon Linux). You can use it to quickly launch the software without any configuration.
 
1. Select to Launch instance
1. Pre-condition: Create an EC2 Role with the Get/List permission to AWS IAM
2. Search for public AMI with ID ami-19533f23 (NEW - with IAM password authentication ami-e16b02db)
3. Select at least t2.small instance type
4. Assign the instance the above-mentioned role
5. Assign a security group which has port 10389 opened to the LDAP clients (that's where the LDAP server will be running)
6. Launch the instance

> *Note:* Never run this instance in public subnet with port 10389 open to the Internet

> *Note:* Make sure you read the section about [security hardening](#security-notes)

After a few second, verify that the LDAP works by executing the following command:

    ldapsearch -H ldap://<instance IP>:10389 -D "uid=admin,ou=system" -x -w secret -b "dc=iam,dc=aws,dc=org" "(objectclass=posixaccount)"
    
That's it. You can then customize the instance or AMI to your configuration.

Quick start from pre-build binary
=================================

Download the binary package from [AWS_IAM_ApacheDS](https://s3-ap-southeast-2.amazonaws.com/aws-iam-apacheds/apacheds-0.2.zip).
Alternatively, you can read [build instruction](BUILD.md) on how to build the same binary package.
This package contains a self-contained installation of ApacheDS 2.0.0-M17 with AWS IAM bridge. It is designed to be used
straight away on any Linux system which has Java 6 without any manual configuration. For example, it can be embedded into
an AWS AMI and used for all your servers to allow the AWS IAM authentication of Linux users.

To start using the server, you need to configure your AWS access and secret keys that the authenticator is going to use
to fetch the users and groups, and authenticate with AWS IAM on their behalf.

1. Extract the contents of the archive

2. Configure AWS access credentials

    The application uses default credentials provider so all typical means of specifying the credentials will work (e.g. environment variable).
    For details, see the AWS SDK documentation [Providing Credentials](http://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/credentials.html).

    The specified user must have the following permissions:

       - Read access to IAM List* and Get* operations.

3. (Optional) Customize some properties via the config file

    The config file is either specified as the iamLdapPropertiesPath Java property, or is at /etc/iam_ldap.conf. The file has Java property files format.

    The following properties can be defined:

    - pollPeriod:  frequency with which the server will refresh the credentials from IAM. Default is 600 seconds.
    - rootDN: the root DN for the authentication information. An new partition will be created at this location. Default is "dc=iam,dc=aws,dc=org".
    - validator: the type of validator to be used. Can be either "iam_secret_key" (default), or "iam_password". iam_secret_key expects IAM Secret Access
    Key as the password for the user, while "iam_password" expects the actual IAM account password (the same the user would use to login into AWS Console).

    If no config file is specified, the defaults above are used.

4. Start the ApacheDS server (assuming Linux):

        cd bin
        bash apacheds.sh &
        sleep 10

5. After that the server should be filled with the users/groups.

    You can verify that by executing the following (replace dc=example,dc=com with your root DN):

        ldapsearch -H ldap://localhost:10389 -D "uid=admin,ou=system" -x -w secret -b "dc=iam,dc=aws,dc=org" "(objectclass=posixaccount)"

    You should get a list of your IAM accounts.

6. (Optional) Configure propagation of the access credentials into user session

    There is an ability to propagate the AWS Access Key and Secret Key into the logged-in user session allowing that user to execute the AWS command (for example, with awscli)
    using their own credentials without the need to pre-configure them in the instance.

    In order to enable it:

        apt-get install python-pam python-ldap
        pip install configparser
        cp bin/pam_accesskey.py /lib/security
        cp bin/etc_aws_iam_ldap.conf /etc/aws_iam_ldap.conf

    The modify `/etc/pam.d/common-auth` by adding the following line at the end:

        auth optional pam_python.so pam_permit.py

    You can change `optional` to a more strict requirement if you consider this behavior critical.

    You would need to edit /etc/aws_iam_ldap.conf with the correct URI and base DN

*Note:* it is up to you to configure the PAM LDAP or similar authentication mechanism. You can use this guide for configuration <http://wiki.debian.org/LDAP/PAM/>.
Pick the `libnss-ldapd`/`libpam-ldapd` option as I found it to work the best with ApacheDS (on Ubuntu). You'll also need to:

- modify /etc/ssh/sshd_config by commenting out the line of `PasswordAuthentication no`.
- modify /etc/pam.d/common-session by adding this line somewhere close to the end: `session     required      pam_mkhomedir.so skel=/etc/skel umask=0022`

After successful configuration of LDAP and NSLCD you should be able to see the users and groups using `getent passwd` and `getent group`
If that works, you should now be able to login using the username of one of your IAM accounts, and using the secret key as the password.

Config file
===========

The config file is either specified as the iamLdapPropertiesPath Java property, or is at /etc/iam_ldap.conf. The file has Java property files format.

The following properties can be defined:

- pollPeriod:  frequency with which the server will refresh the credentials from IAM. Default is 600 seconds.
- rootDN: the root DN for the authentication information. An new partition will be created at this location, and then "ou=users" and "ou=groups". 
    Default is "dc=iam,dc=aws,dc=org".
- validator: the type of validator to be used. Can be either "iam_secret_key" (default), or "iam_password". iam_secret_key expects IAM Secret Access
    Key as the password for the user, while "iam_password" expects the actual IAM account password (the same the user would use to login into AWS Console).

If no config file is specified, the defaults above are used.

Security notes
==============

The default configuration is _INSECURE_ however you are free to alter it to your requirements. It should not affect the behavior of the custom authenticator.

You may want to change the following defaults:

- The default `uid=admin,ou=system` password, `secret` by default
- Disable anonymous binds
- Enable TLS/SASL or LDAPS
- Change the rootDN where the users/groups are stored
- Enable ACL and change the permissions for the `dn: ads-authenticatorid=awsiamauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config`,
  as well as the rootDN.

    This entry stores the configuration for the authenticator, and rootDN stores all the information about accounts. You need to prevent any logged in users
    from modifying the account's keys and group information (only admin should be allowed to do that).

Configuring an existing ApacheDS LDAP server (Obsolete)
============================================
At the moment, the plugin requires a custom version of ApacheDS so manual configuration is unlikely. However, in a rare case when you want to reconfigure the provided custom instance,
here is the list of steps you need to perform:

1. Copy an existing default instance from Apache DS 2.0.0-M17 (or newer)

    Note that the following steps may only work on the specified default instance - there may be conflicting configuration
    in some other custom instance
    
2. Copy the apacheds_awsiam.jar and dependent jars into the "lib" folder of the instance

3. Starts the instance. The following assumes the instance is running on port 10389 on localhost.

4. Import IAM authenticator configuration:

        ldapmodify -H ldap://localhost:10389 -D uid=admin,ou=system -w secret -x -f iam.ldif

5. Restart the instance

    You should not see any errors in the console. Wait 15 seconds (scan starts after 10) and then execute user's search:

        ldapsearch -D "uid=admin,ou=system" -w secret -x -b "dc=iam,dc=aws,dc=org" "(objectclass=posixaccount)"

    You should see your IAM accounts and if your PAM/LDAP is configured you should now be able to login using one of them.

After that you are strongly advised to follow the security hardening steps described in *Security notes*. Ideally, never expose this instance to the open Internet, only use it within a VPC in a private subnet.

Assumptions
===========
- Users have only one access key. If you users have more than one access key, the authenticator will pick the first of them for authentication.
