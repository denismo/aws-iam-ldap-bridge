package com.denismo.aws.iam;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:40 PM
 */
public class IAMPasswordValidator {
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException {
        String accessKey = user.get("accessKey").getString();
        System.err.printf("Verifying user %s with accessKey %s and secretKey %s",
                user.get("uid").getString(), accessKey, pw);
        AWSCredentials creds = new BasicAWSCredentials(accessKey, pw);
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(creds);
        try {
            client.getAccountSummary();
        } catch (AmazonClientException e) {
            System.err.println(e.getMessage());
            return false;
        } finally {
            client.shutdown();
        }
        return true;
    }
}
