package com.denismo.aws.iam;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by jweede on 4/5/16.
 */
public class IAMDualValidator implements _IAMPasswordValidator {
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(IAMDualValidator.class);

    private List<_IAMPasswordValidator> validators;

    public IAMDualValidator() {
        this.validators = new LinkedList<_IAMPasswordValidator>();
        this.validators.add(new IAMAccountPasswordValidator());
        this.validators.add(new IAMSecretKeyValidator());
    }

    @Override
    public boolean verifyIAMPassword(Entry user, String pw) throws LdapInvalidAttributeValueException, LdapAuthenticationException {
        for (_IAMPasswordValidator v : this.validators) {
            LOG.debug("Dual Validator: trying {} for {}", v.getClass().getName(), user.get("uid").toString());
            if (v.verifyIAMPassword(user, pw)) {
                return true;
            }
        }
        return false;
    }
}
