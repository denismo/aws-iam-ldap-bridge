package com.denismo.aws.iam;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:40 PM
 */
public class IAMPasswordValidator {
    private static final Logger LOG = LoggerFactory.getLogger(IAMPasswordValidator.class);
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        boolean role = false;
        AWSCredentials creds;
        if (isRole(user)) {
            role = true;
            String[] parts = pw.split("\\|");
            if (parts == null || parts.length < 3) throw new LdapAuthenticationException();
            creds = new BasicSessionCredentials(parts[0], parts[1], parts[2]);
        } else {
            creds = new BasicAWSCredentials(user.get("accessKey").getString(), pw);
        }
        LOG.debug("Verifying {} {} with accessKey <hidden> and secretKey <hidden>",
                role ? "role":"user", user.get("uid").getString());
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

    private boolean isRole(Entry user) {
        return user.hasObjectClass("iamrole");
    }
}
