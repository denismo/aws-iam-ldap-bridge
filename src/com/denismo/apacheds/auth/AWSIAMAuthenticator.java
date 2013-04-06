package com.denismo.apacheds.auth;

import com.denismo.aws.iam.IAMPasswordValidator;
import com.denismo.aws.iam.LDAPIAMPoller;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.authn.AbstractAuthenticator;
import org.apache.directory.server.core.authn.SimpleAuthenticator;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.SocketAddress;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:31 PM
 */
// TODO: Proper logging
// TODO: ant based build file with Ivy dependencies
public class AWSIAMAuthenticator extends AbstractAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(AWSIAMAuthenticator.class);

    private final IAMPasswordValidator validator = new IAMPasswordValidator();
    private LDAPIAMPoller poller;
    private SimpleAuthenticator delegatedAuth;

    public AWSIAMAuthenticator() {
        super(AuthenticationLevel.SIMPLE);
        delegatedAuth = new SimpleAuthenticator();
        LOG.info("AWSIAMAuthenticator has been created");
    }

    @Override
    protected void doInit() {
        super.doInit();
        LOG.info("Init called");
        if (getDirectoryService() != null) {
            try {
                delegatedAuth.init(getDirectoryService());
                poller = new LDAPIAMPoller(getDirectoryService());
                poller.start();
            } catch (LdapException e) {
                LOG.error("Exception initializing delegated SimpleAuthenticator", e);
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public LdapPrincipal authenticate(BindOperationContext bindContext) throws Exception {
        if (!isAWSAccount(bindContext)) {
            LOG.info("Skipping " + bindContext.getDn() + " - not an AWS account");
            if (delegatedAuth == null) {
                LOG.error("Delegated auth is null");
                return null;
            }
            return delegatedAuth.authenticate(bindContext);
        }

        LOG.info("Authenticating " + bindContext.getDn());

        byte[] password = bindContext.getCredentials();

        LookupOperationContext lookupContext = new LookupOperationContext( getDirectoryService().getAdminSession(),
                bindContext.getDn(), SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

        Entry userEntry = getDirectoryService().getPartitionNexus().lookup( lookupContext );

        if (validator.verifyIAMPassword(userEntry, new String(password))) {
            LdapPrincipal principal = new LdapPrincipal( getDirectoryService().getSchemaManager(), bindContext.getDn(),
                    AuthenticationLevel.SIMPLE, password);
            IoSession session = bindContext.getIoSession();

            if ( session != null )
            {
                SocketAddress clientAddress = session.getRemoteAddress();
                principal.setClientAddress( clientAddress );
                SocketAddress serverAddress = session.getServiceAddress();
                principal.setServerAddress( serverAddress );
            }

            bindContext.setEntry( new ClonedServerEntry( userEntry ) );
            return principal;
        } else {
            // Bad password ...
            String message = I18n.err( I18n.ERR_230, bindContext.getDn().getName() );
            LOG.info( message );
            throw new LdapAuthenticationException( message );
        }
    }

    private boolean isAWSAccount(BindOperationContext bindContext) throws LdapException {
        LookupOperationContext lookupContext = new LookupOperationContext( getDirectoryService().getAdminSession(),
                bindContext.getDn(), SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

        Entry userEntry = getDirectoryService().getPartitionNexus().lookup( lookupContext );
        return userEntry.hasObjectClass("iamaccount");
    }
}
