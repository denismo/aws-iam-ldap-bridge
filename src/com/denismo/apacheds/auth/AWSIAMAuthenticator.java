/*
 * Copyright (c) 2013 Denis Mikhalkin.
 *
 * This software is provided to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.  You may obtain a copy of the
 * License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.denismo.apacheds.auth;

import com.denismo.aws.iam.IAMAccountPasswordValidator;
import com.denismo.aws.iam.IAMSecretKeyValidator;
import com.denismo.aws.iam.LDAPIAMPoller;
import com.denismo.aws.iam._IAMPasswordValidator;
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketAddress;
import java.util.Properties;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:31 PM
 */
public class AWSIAMAuthenticator extends AbstractAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(AWSIAMAuthenticator.class);

    public static class Config {
        public static final String PASSWORD_VALIDATOR = "iam_password";
        public String rootDN = "dc=iam,dc=aws,dc=org";
        public int pollPeriod = 600;
        public String validator = "iam_secret_key"; // other options: iam_secret_key

        public boolean isSecretKeyLogin() {
            return !PASSWORD_VALIDATOR.equals(validator);
        }
    }

    private static Config s_config;
    public static void setConfig(Config config) {
        s_config = config;
    }

    public static Config getConfig() {
        return s_config;
    }

    private _IAMPasswordValidator validator;
    private LDAPIAMPoller poller;
    private SimpleAuthenticator delegatedAuth;
    private boolean disabled;

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

                readIAMProperties();

                poller = new LDAPIAMPoller(getDirectoryService());
                poller.start();
            } catch (Exception e) {
                LOG.error("Exception initializing AWSIAMAuthenticator", e);
                disabled=true;
            }
        } else {
            LOG.info("doInit without directory service");
        }
    }


    private void readIAMProperties() {
        String propsPath = System.getProperty("iamLdapPropertiesPath", "/etc/iam_ldap.conf");
        File propsFile = new File(propsPath);
        // Read the config file if exists
        if (propsFile.exists()) {
            try {
                Properties props = new Properties();
                props.load(new FileInputStream(propsFile));
                AWSIAMAuthenticator.Config config = new AWSIAMAuthenticator.Config();
                if (props.containsKey("pollPeriod")) config.pollPeriod = Integer.parseInt(props.getProperty("pollPeriod"));
                if (props.containsKey("rootDN")) config.rootDN = props.getProperty("rootDN");
                if (props.containsKey("validator")) config.validator = props.getProperty("validator");
                AWSIAMAuthenticator.setConfig(config);
            } catch (IOException e) {
                LOG.error("Unable to read IAM LDAP config file");
                AWSIAMAuthenticator.setConfig(new AWSIAMAuthenticator.Config());
            }
        } else {
            // Populate from defaults
            AWSIAMAuthenticator.setConfig(new AWSIAMAuthenticator.Config());
        }
        createValidator();
    }

    private void createValidator() {
        if (Config.PASSWORD_VALIDATOR.equals(getConfig().validator)) {
            validator = new IAMAccountPasswordValidator();
        } else {
            validator = new IAMSecretKeyValidator();
        }
    }

    @Override
    public LdapPrincipal authenticate(BindOperationContext bindContext) throws Exception {
        if (!isAWSAccount(bindContext) || disabled) {
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
