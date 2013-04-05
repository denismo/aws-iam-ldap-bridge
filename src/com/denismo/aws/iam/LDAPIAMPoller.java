package com.denismo.aws.iam;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.*;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.*;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:53 PM
 */
public class LDAPIAMPoller {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPIAMPoller.class);

    private BasicAWSCredentials credentials;
    private UIDAllocator userIDAllocator;
    private UIDAllocator groupIDAllocator;
    private DirectoryService directory;
    private int pollPeriod = 600;
    private String groupsDN;
    private String usersDN;
    private String rootDN;
    private String GROUP_FMT;
    private String USER_FMT;
    private String accessKey;
    private String secretKey;

    public LDAPIAMPoller(DirectoryService directoryService) {
        this.directory = directoryService;

        readConfig();
        credentials = new BasicAWSCredentials(accessKey, secretKey);
        userIDAllocator = new UIDAllocator(credentials, "Users");
        groupIDAllocator = new UIDAllocator(credentials, "Groups");
        LOG.info("IAMPoller created");
    }

    private void readConfig() {
        try {
            LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                    directory.getDnFactory().create("cn=config,ads-authenticatorid=awsiamauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);
            Entry config = directory.getPartitionNexus().lookup(lookupContext);
            if (config.get("accessKey") != null) {
                accessKey = config.get("accessKey").getString();
            }
            if (config.get("secretKey") != null) {
                secretKey = config.get("secretKey").getString();
            }
            if (config.get("rootDN") != null) {
                rootDN = config.get("rootDN").getString();
            }
            groupsDN = "ou=groups," + rootDN;
            usersDN = "ou=users," + rootDN;
            GROUP_FMT = "cn=%s," + groupsDN;
            USER_FMT = "uid=%s," + usersDN;
            ensureRootDN();

            if (config.get("pollPeriod") != null) {
                pollPeriod = Integer.parseInt(config.get("pollPeriod").getString());
            }
        } catch (Throwable e) {
            LOG.error("Exception reading config for LDAPIAMPoller", e);
        }
    }

    private void ensureRootDN() throws LdapException {
        directory.getPartitionNexus().hasEntry(new HasEntryOperationContext(directory.getAdminSession(),
                directory.getDnFactory().create(rootDN)));
        if (!directory.getPartitionNexus().hasEntry(new HasEntryOperationContext(directory.getAdminSession(),
                directory.getDnFactory().create(usersDN)))) {
            createEntry(usersDN, "organizationalUnit");
        }
        if (!directory.getPartitionNexus().hasEntry(new HasEntryOperationContext(directory.getAdminSession(),
                directory.getDnFactory().create(groupsDN)))) {
            createEntry(groupsDN, "organizationalUnit");
        }
    }

    private void createEntry(String dn, String clazz) throws LdapException {
        Dn dnObj = directory.getDnFactory().create(dn);
        Rdn rdn = dnObj.getRdn(0);
        DefaultEntry entry = new DefaultEntry(directory.getSchemaManager(), dn);
        entry.put(rdn.getType(), rdn.getValue());
        entry.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        entry.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        entry.put("objectclass", clazz);
        add(entry);
    }

    private void pollIAM() {
        LOG.info("*** Updating accounts from IAM");
        try {
            populateGroupsFromIAM();
            populateUsersFromIAM();
        } catch (Throwable e) {
            LOG.error("Exception polling", e);
        }
        LOG.info("*** IAM account update finished");
    }
    private void populateGroupsFromIAM() {
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);

        try {
            ListGroupsResult res = client.listGroups();
            while (true) {
                for (Group group : res.getGroups()) {
                    try {
                        addGroup(group);
                        LOG.info("Added group " + group.getGroupName() + " at " + groupsDN);
                    } catch (Throwable e) {
                        LOG.error("Exception processing group " + group.getGroupName(), e);
                    }
                }
                if (res.isTruncated()) {
                    res = client.listGroups(new ListGroupsRequest().withMarker(res.getMarker()));
                } else {
                    break;
                }
            }
        } finally {
            client.shutdown();
        }
    }

    private void addGroup(Group iamGroup) throws LdapException {
        Entry existingGroup = getExistingGroup(iamGroup);
        if (existingGroup != null) {
            return;
        }

        String gid = allocateGroupID(iamGroup.getGroupName());
        Entry group = new DefaultEntry(directory.getSchemaManager(), directory.getDnFactory().create(String.format(GROUP_FMT, iamGroup.getGroupName())));
        group.put(SchemaConstants.OBJECT_CLASS_AT, "posixGroup", "iamgroup");
        group.put("gidNumber", gid);
        group.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        group.put(SchemaConstants.CN_AT, iamGroup.getGroupName());
        group.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(group);
    }

    private Entry getExistingGroup(Group iamGroup) throws LdapException {

        LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                directory.getDnFactory().create(String.format(GROUP_FMT, iamGroup.getGroupName())),
                SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

        try {
            Entry groupEntry = directory.getPartitionNexus().lookup( lookupContext );
            if (groupEntry != null && groupEntry.hasObjectClass("iamgroup")) {
                return groupEntry;
            }
        } catch (LdapNoSuchObjectException e) {
            // Fallthrough
        }
        return null;
    }

    private void add(Entry entry) throws LdapException {
        directory.getPartitionNexus().add(new AddOperationContext(directory.getAdminSession(), entry));
    }

    private String allocateGroupID(String groupName) {
        return groupIDAllocator.allocateUID(groupName);
    }

    private void populateUsersFromIAM() {
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);

        try {
            ListUsersResult res = client.listUsers();
            while (true) {
                for (User user : res.getUsers()) {
                    try {
                        Collection<Group> groups = client.listGroupsForUser(new ListGroupsForUserRequest(user.getUserName())).getGroups();
                        Group primaryGroup = groups.size() > 0 ? groups.iterator().next() : null;
                        if (primaryGroup == null) {
                            LOG.warn("Unable to determine primary group for " + user.getUserName());
                            continue;
                        }
                        Entry groupEntry = getExistingGroup(primaryGroup);
                        if (groupEntry == null) {
                            LOG.warn("Unable to retrieve matching group entry for group " + primaryGroup.getGroupName() + " user " + user.getUserName());
                            continue;
                        }
                        addUser(user, getUserAccessKey(client, user), groupEntry);
                        LOG.info("Added user " + user.getUserName());
                    } catch (Throwable e) {
                        LOG.error("Exception processing user " + user.getUserName(), e);
                    }
                }
                if (res.isTruncated()) {
                    res = client.listUsers(new ListUsersRequest().withMarker(res.getMarker()));
                } else {
                    break;
                }
            }
        } finally {
            client.shutdown();
        }
    }

    private String getUserAccessKey(AmazonIdentityManagementClient client, User user) {
        ListAccessKeysResult res = client.listAccessKeys(new ListAccessKeysRequest().withUserName(user.getUserName()));
        for (AccessKeyMetadata meta : res.getAccessKeyMetadata()) {
            if ("Active".equals(meta.getStatus())) {
                return meta.getAccessKeyId();
            }
        }
        return null;
    }

    private void addUser(User user, String accessKey, Entry group) throws LdapException {
        if (accessKey == null) {
            LOG.info("User " + user.getUserName() + " has no active access keys");
            return;
        }
        Entry existingUser = getExistingUser(user);
        if (existingUser != null) {
            directory.getAdminSession().modify(existingUser.getDn(),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "accessKey", accessKey),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "gidNumber", group.get("gidNumber").getString())
            );
            if (!group.contains("memberUid", user.getUserName())) {
                directory.getAdminSession().modify(group.getDn(),
                        new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "memberUid", user.getUserName()));
            }
            return;
        }

        DefaultEntry ent = new DefaultEntry(directory.getSchemaManager(), directory.getDnFactory().create(String.format(USER_FMT, user.getUserName())));
        ent.put(SchemaConstants.OBJECT_CLASS_AT, "posixAccount", "shadowAccount", "iamaccount");
        ent.put("accessKey", accessKey);
        ent.put("uid", user.getUserName());
        ent.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        ent.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        ent.put("cn", user.getUserName());
        ent.put("uidNumber", allocateUserID(user.getUserName()));
        ent.put("gidNumber", group.get("gidNumber").getString());
        ent.put("shadowLastChange", "10877");
        ent.put("shadowExpire", "-1");
        ent.put("shadowInactive", "-1");
        ent.put("shadowFlag", "0");
        ent.put("shadowWarning", "7");
        ent.put("shadowMin", "0");
        ent.put("shadowMax", "999999");
        ent.put("loginshell", "/bin/bash");
        ent.put("homedirectory", "/home/" + user.getUserName());
        add(ent);

        directory.getAdminSession().modify(group.getDn(),
                new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "memberUid", user.getUserName()));
    }

    private Entry getExistingUser(User user) throws LdapException {
        LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                directory.getDnFactory().create(String.format(USER_FMT, user.getUserName())), SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

        try {
            Entry userEntry = directory.getPartitionNexus().lookup( lookupContext );
            if (userEntry != null && userEntry.hasObjectClass("iamaccount")) {
                return userEntry;
            }
        } catch (LdapNoSuchObjectException e) {
            // Fallthrough
        }
        return null;
    }

    private String allocateUserID(String name) {
        return userIDAllocator.allocateUID(name);
    }

    public void start() {
        LOG.info("IAMPoller started");
        Runnable poll = new Runnable() {
            @Override
            public void run() {
                pollIAM();
            }
        };
        Executors.newScheduledThreadPool(1).scheduleAtFixedRate(poll, 10, pollPeriod, TimeUnit.SECONDS);
    }
}
