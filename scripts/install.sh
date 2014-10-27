#!/bin/bash

curl -O https://s3-ap-southeast-2.amazonaws.com/aws-iam-apacheds/apacheds-0.1.zip
unzip -q apacheds-0.1.zip
cd apacheds/instances
unzip -q default

sudo bash <<EOF
echo "
runuser -l ec2-user -c 'JAVA_HOME=/usr/lib/jvm/jre bash /home/ec2-user/apacheds/bin/apacheds.sh start ' > /home/ec2-user/apacheds/start.log 2>&1
" >> /etc/rc.local
EOF

sudo bash <<EOF
echo "
This AMI contains the LDAP-to-IAM bridge. See https://github.com/denismo/aws-iam-ldap-bridge for more details" >> /etc/motd
echo "(c) 2014 Denis Mikhalkin" >> /etc/motd
EOF

sudo yum -y update
sudo shred -u /etc/ssh/*_key /etc/ssh/*_key.pub
sudo shred -u ~/.*history
shred -u ~/.*history
exit 0
