[![Build Status](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/badge/icon)](https://buildhive.cloudbees.com/job/denismo/job/aws-iam-ldap-bridge/)

Building AWS IAM ApacheDS bridge
================================

The project is using Ant build script build.xml with Ivy module support. Either import it into Intellij IDEA or Eclipse, or run ant directly in command line.

The target which builds the binary installable package is called "dist" so the command to build it would be

        ant dist

You can then upload this package to a Linux box which will be your LDAP server, extract it and follow the [installation instruction](INSTALL.md)