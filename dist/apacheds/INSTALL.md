TODO:
- manual configuration
- IAM permissions

Introduction
============

This package contains a self-contained installation of ApacheDS 2.0.0-M11 with AWS IAM bridge. It is designed to be used
straight away on any Linux system which has Java 6 without any manual configuration. For example, it can be embedded into
an AMI and used for all your servers to allow the AWS IAM authentication of Linux users.

The bridge periodically populates the LDAP directory location with the users and groups from AWS IAM, and allows for
authenticating the users against AWS IAM using their AWS IAM Secret Keys as passwords.

After that, you can login into Linux using the user names of AWS IAM account, and by typing the secret key as the
password. After login, the user will have the Linux groups corresponding to the IAM groups that were assigned to them.

Note: The user's AWS Secret Keys are never stored in any persistent storage or logs.

By default, the users are cached at ou=users,dc=example,dc=com and groups as ou=groups,dc=example,dc=com. You can change
that by modifying the rootDN in auth.ldif and importing it back into the server.

Quick start
===========

To start using the server, you need to configure your AWS access and secret keys that the authenticator is going to use
to fetch the users and groups, and authenticate with AWS IAM on their behalf.

1. Edit the modify.ldif and change the values for accessKey and secretKey

2. Start the ApacheDS server (assuming Linux):
 > apacheds&

 > sleep 10

3. Apply the AWS configuration
 > ldapmodify -H ldap://localhost:10389 -D uid=admin,ou=system -w secret -x -f modify.ldif

4. Restart the ApacheDS server
 > killall apacheds

 > apacheds&

After that the server should be filled with the users/groups. You can verify that by executing the following:
 >  ldapsearch -H ldap://localhost:10389 -D "uid=admin,ou=system" -x -w secret -b "dc=example,dc=com" "(objectclass=posixaccount)"

You should get a list of your IAM accounts.

Note: it is up to you to configure the PAM LDAP or similar authentication mechanism. You can use this guide for configuration:
- http://wiki.debian.org/LDAP/PAM
Pick "libnss-ldapd/libpam-ldapd" option as I found it to work the best with ApacheDS. You'll also need to modify /etc/ssh/sshd_config by
 commenting out the line of #PasswordAuthentication no.

After successful configuration of LDAP and NSLCD you should be able to see the users and groups using "getent passwd" and "getent group".
If that works, you should now be able to login using the username of one of your IAM accounts, and using the secret key as the password.

Security notes
==============

The default configuration is INSECURE however it is orthogonal to the configuration of the AWS IAM authenticator so it
is up to you to secure the system according to your requirements.

You may want to change the following defaults:
- The default "uid=admin,ou=system" password, "secret" by default
- Disable anonymous binds
- Enable TLS/SASL or LDAPS
- Change the rootDN where the users/groups are stored
- Enable ACL and change the permissions for the dn: ads-authenticatorid=awsiamauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config
  This entry stores the AWS Access Key and Secret Key for the authenticator

Configuring an existing ApacheDS LDAP server
============================================
If you installed the ApacheDS by other means, you can add the authenticator to it manually:
TBD

Assumptions
===========
- Users have only one access key. If you users have more than one access key, the authenticator may randomly pick one
of them for authentication. You can check which one it picked by quering the cached LDAP information for that user.