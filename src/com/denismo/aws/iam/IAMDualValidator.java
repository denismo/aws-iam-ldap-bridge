package com.denismo.aws.iam;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

/**
 * Created by jweede on 4/5/16.
 */
public class IAMDualValidator implements _IAMPasswordValidator {
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(IAMDualValidator.class);

    // Regex is mentioned in this blog post
    // https://aws.amazon.com/blogs/security/a-safer-way-to-distribute-aws-credentials-to-ec2/
    private static Pattern secret_key_pattern = Pattern.compile("^[A-Za-z0-9/+=]{40,}$");

    private _IAMPasswordValidator pw_validator;
    private _IAMPasswordValidator secret_key_validator;

    public IAMDualValidator() {
        this.pw_validator = new IAMAccountPasswordValidator();
        this.secret_key_validator = new IAMSecretKeyValidator();
    }

    private boolean secretKeyAuth(Entry user, String pw, String username) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        LOG.info("Dual Validator: trying secret key auth for {}", username);
        return this.secret_key_validator.verifyIAMPassword(user, pw);
    }

    private boolean pwAuth(Entry user, String pw, String username) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        LOG.info("Dual Validator: trying IAM pw auth for {}", username);
        return this.pw_validator.verifyIAMPassword(user, pw);
    }

    @Override
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        String username = user.get("uid").toString();
        if ( IAMDualValidator.secret_key_pattern.matcher(pw).matches() ) {
            return this.secretKeyAuth(user, pw, username) || this.pwAuth(user, pw, username);
        } else {
            return this.pwAuth(user, pw, username) || this.secretKeyAuth(user, pw, username);
        }
    }
}
