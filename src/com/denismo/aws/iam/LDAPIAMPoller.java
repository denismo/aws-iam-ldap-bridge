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

package com.denismo.aws.iam;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.*;
import com.denismo.apacheds.auth.AWSIAMAuthenticator;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.*;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.normalizers.ConcreteNameComponentNormalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.NameComponentNormalizer;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.*;
import org.apache.directory.server.core.api.normalization.FilterNormalizingVisitor;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.xdbm.Index;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:53 PM
 */
public class LDAPIAMPoller {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPIAMPoller.class);
    private static final Object ID_LOCK = new Object();
    public static final String ID_GENERATOR = "idGenerator";

    private AWSCredentialsProvider credentials;
    private DirectoryService directory;
    private int pollPeriod = 600;
    private String groupsDN;
    private String usersDN;
    private String rootDN;
    private String GROUP_FMT;
    private String USER_FMT;
    private String ROLE_FMT;
    private String rolesDN;
    private boolean firstRun = true;
    private Entry configEntry;
    private ScheduledFuture<?> schedule;

    public LDAPIAMPoller(DirectoryService directoryService) throws LdapException {
        this.directory = directoryService;

        credentials = new DefaultAWSCredentialsProviderChain();
        try {
            credentials.getCredentials(); // throws
        } catch (AmazonClientException ex) {
            LOG.error("AWS credentials error", ex);
            throw new LdapException("Unable to initialze AWS poller - cannot retrieve valid credentials");
        }
        LOG.info("IAMPoller created");
    }

    private void createStructure() throws Exception {
        if (!firstRun) return;
        firstRun = false;
        try {
            String rootDN = AWSIAMAuthenticator.getConfig().rootDN;
            Dn dnIAM = directory.getDnFactory().create(rootDN);
            if (!exists(dnIAM)) {
                Partition iamPartition = addPartition("iam", rootDN, directory.getDnFactory());

                // Index some attributes on the apache partition
                addIndex(iamPartition, "objectClass", "ou", "uid", "gidNumber", "uidNumber", "cn");

                Entry entryIAM = new DefaultEntry(directory.getSchemaManager(), dnIAM, "objectClass: top", "objectClass: domain", "dc: iam",
                        "entryCsn: " + directory.getCSN(), SchemaConstants.ENTRY_UUID_AT + ": " + UUID.randomUUID().toString());
                iamPartition.add(new AddOperationContext(null, entryIAM));

//                Entry entryIAM = directory.newEntry(dnIAM);
//                entryIAM.add("objectClass", "top", "domain");
//                entryIAM.add("dc", "iam"); // TODO What if rootDN does not have dc=iam?
//                directory.getAdminSession().add(entryIAM);
            }
            readConfig();
        } catch (Exception e) {
            LOG.error("Exception preparing structure", e);
            schedule.cancel(false);
            throw new RuntimeException("Unable to initialize poller");
        }
    }

    private boolean exists(Dn dnIAM) {
        try {
            return directory.getAdminSession().exists(dnIAM);
        } catch (LdapException e) {
            return false;
        }
    }

    /**
     * Add a new partition to the server
     *
     * @param partitionId The partition Id
     * @param partitionDn The partition DN
     * @param dnFactory the DN factory
     * @return The newly added partition
     * @throws Exception If the partition can't be added
     */
    private Partition addPartition( String partitionId, String partitionDn, DnFactory dnFactory ) throws Exception
    {
        DirectoryService service = directory;
        // Create a new partition with the given partition id
        JdbmPartition partition = new JdbmPartition(service.getSchemaManager()/*, dnFactory*/);
        partition.setId( partitionId );
        partition.setPartitionPath(new File(service.getInstanceLayout().getPartitionsDirectory(), partitionId).toURI());
        partition.setSuffixDn(dnFactory.create(partitionDn));
        partition.initialize();
        service.addPartition( partition );

        return partition;
    }


    /**
     * Add a new set of index on the given attributes
     *
     * @param partition The partition on which we want to add index
     * @param attrs The list of attributes to index
     */
    private void addIndex( Partition partition, String... attrs )
    {
        // Index some attributes on the apache partition
        Set<Index<?,?,String>> indexedAttributes = new HashSet<Index<?, ?, String>>();

        for ( String attribute : attrs )
        {
            indexedAttributes.add( new JdbmIndex( attribute, false ) );
        }

        ( ( JdbmPartition ) partition ).setIndexedAttributes(indexedAttributes);
    }

    private void readConfig() {
        try {
            LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                    directory.getDnFactory().create("cn=config,ads-authenticatorid=awsiamauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config"),
                    SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);
            configEntry = directory.getPartitionNexus().lookup(lookupContext);
            AWSIAMAuthenticator.Config config = AWSIAMAuthenticator.getConfig();
            rootDN = config.rootDN;
            pollPeriod = config.pollPeriod;

            groupsDN = "ou=groups," + rootDN;
            usersDN = "ou=users," + rootDN;
            rolesDN = "ou=roles," + rootDN;
            GROUP_FMT = "cn=%s," + groupsDN;
            USER_FMT = "uid=%s," + usersDN;
            ROLE_FMT = "uid=%s,ou=roles," + rootDN;
            ensureDNs();
        } catch (Throwable e) {
            LOG.error("Exception reading config for LDAPIAMPoller", e);
        }
    }

    private void ensureDNs() throws LdapException, IOException, ParseException, CursorException {
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
        if (!directory.getPartitionNexus().hasEntry(new HasEntryOperationContext(directory.getAdminSession(),
                directory.getDnFactory().create(rolesDN)))) {
            createEntry(rolesDN, "organizationalUnit");
        }
    }

    private void clearDN(String dnStr) throws LdapException, ParseException, IOException, CursorException {
        Dn dn = directory.getDnFactory().create(dnStr);
        dn.apply(directory.getSchemaManager());
        ExprNode filter = FilterParser.parse(directory.getSchemaManager(), "(ObjectClass=*)");
        NameComponentNormalizer ncn = new ConcreteNameComponentNormalizer( directory.getSchemaManager() );
        FilterNormalizingVisitor visitor = new FilterNormalizingVisitor( ncn, directory.getSchemaManager() );
        filter.accept(visitor);
        SearchOperationContext context = new SearchOperationContext(directory.getAdminSession(),
                dn, SearchScope.SUBTREE, filter, SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);
        EntryFilteringCursor cursor = directory.getPartitionNexus().search(context);
        cursor.beforeFirst();
        Collection<Dn> dns = new ArrayList<Dn>();
        while (cursor.next()) {
            Entry ent = cursor.get();
            if (ent.getDn().equals(dn)) continue;
            dns.add(ent.getDn());
        }
        cursor.close();

        LOG.info("Deleting " + dns.size() + " items from under " + dnStr);
        for (Dn deleteDn: dns) {
            directory.getAdminSession().delete(deleteDn);
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
        if (!directory.isStarted()) return;

        LOG.info("*** Updating accounts from IAM");
        try {
//            clearDNs();
            createStructure();
            populateGroupsFromIAM();
            populateUsersFromIAM();
//            populateRolesFromIAM();
            LOG.info("*** IAM account update finished");
        } catch (Throwable e) {
            LOG.error("Exception polling", e);
        }
    }

    private void clearDNs() throws LdapException, IOException, ParseException, CursorException {
        if (firstRun) {
            firstRun = false;
            clearDN(usersDN);
            clearDN(groupsDN);
            clearDN(rolesDN);
        }
    }

    private void populateRolesFromIAM() {
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);

        try {
            ListRolesResult res = client.listRoles();
            while (true) {
                for (Role role : res.getRoles()) {
                    try {
                        Entry groupEntry = getOrCreateRoleGroup(role);
                        addRole(role, groupEntry);
                        LOG.info("Added role " + role.getRoleName() + " at " + rolesDN);
                    } catch (Throwable e) {
                        LOG.error("Exception processing role " + role.getRoleName(), e);
                    }
                }
                if (res.isTruncated()) {
                    res = client.listRoles(new ListRolesRequest().withMarker(res.getMarker()));
                } else {
                    break;
                }
            }
        } finally {
            client.shutdown();
        }
    }

    private Entry getOrCreateRoleGroup(Role role) throws LdapException {
        Group group = new Group(role.getPath(), role.getRoleName(), role.getRoleId(), role.getArn(), role.getCreateDate());
        return addGroup(group);
    }

    private void addRole(Role role, Entry roleGroup) throws LdapException {
        Entry existingRole = getExistingRole(role);
        if (existingRole != null) {
            directory.getAdminSession().modify(existingRole.getDn(),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "accessKey", role.getRoleId()),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "gidNumber", roleGroup.get("gidNumber").getString())
            );
            if (!roleGroup.contains("memberUid", role.getRoleName())) {
                directory.getAdminSession().modify(roleGroup.getDn(),
                        new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "memberUid", role.getRoleName()));
            }
            return;
        }

        DefaultEntry ent = new DefaultEntry(directory.getSchemaManager(), directory.getDnFactory().create(String.format(ROLE_FMT, role.getRoleName())));
        ent.put(SchemaConstants.OBJECT_CLASS_AT, "posixAccount", "shadowAccount", "iamaccount", "iamrole");
        ent.put("accessKey", role.getRoleId());
        ent.put("uid", role.getRoleName());
        ent.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        ent.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        ent.put("cn", role.getRoleName());
        ent.put("uidNumber", allocateUserID(role.getArn()));
        ent.put("gidNumber", roleGroup.get("gidNumber").getString());
        ent.put("shadowLastChange", "10877");
        ent.put("shadowExpire", "-1");
        ent.put("shadowInactive", "-1");
        ent.put("shadowFlag", "0");
        ent.put("shadowWarning", "7");
        ent.put("shadowMin", "0");
        ent.put("shadowMax", "999999");
        ent.put("loginshell", "/bin/bash");
        ent.put("homedirectory", "/home/" + role.getRoleName());
        add(ent);

        directory.getAdminSession().modify(roleGroup.getDn(),
                new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "memberUid", role.getRoleName()));
    }

    private Entry getExistingRole(Role role) throws LdapException {
        LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                directory.getDnFactory().create(String.format(ROLE_FMT, role.getRoleName())), SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);

        try {
            Entry roleEntry = directory.getPartitionNexus().lookup( lookupContext );
            if (roleEntry != null && roleEntry.hasObjectClass("iamaccount")) {
                return roleEntry;
            }
        } catch (LdapNoSuchObjectException e) {
            // Fallthrough
        }
        return null;
    }

    private void populateGroupsFromIAM() {
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);

        try {
            ListGroupsResult res = client.listGroups();
            Set<String> groupNames = new HashSet<String>();
            while (true) {
                for (Group group : res.getGroups()) {
                    try {
                        addGroup(group);
                        groupNames.add(group.getGroupName());
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
            removeDeletedGroups(groupNames);
        } finally {
            client.shutdown();
        }
    }

    private void removeDeletedGroups(Set<String> groupNames) {
        Collection<Entry> allGroups = getAllEntries(groupsDN, "iamgroup");
        for (Entry group : allGroups) {
            if (!groupNames.contains(group.get(SchemaConstants.CN_AT).toString())) {
                try {
                    directory.getAdminSession().delete(group.getDn());
                } catch (LdapException e) {
                    LOG.error("Unable to delete group " + group.getDn());
                }
            }
        }
    }

    private Collection<Entry> getAllEntries(String rootDN, String className) {
        try {
            Dn dn = directory.getDnFactory().create(rootDN);
            dn.apply(directory.getSchemaManager());
            ExprNode filter = FilterParser.parse(directory.getSchemaManager(), String.format("(ObjectClass=%s)", className));
            NameComponentNormalizer ncn = new ConcreteNameComponentNormalizer( directory.getSchemaManager() );
            FilterNormalizingVisitor visitor = new FilterNormalizingVisitor( ncn, directory.getSchemaManager() );
            filter.accept(visitor);
            SearchOperationContext context = new SearchOperationContext(directory.getAdminSession(),
                    dn, SearchScope.SUBTREE, filter, SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);
            EntryFilteringCursor cursor = directory.getPartitionNexus().search(context);
            cursor.beforeFirst();
            Collection<Entry> entries = new ArrayList<Entry>();
            while (cursor.next()) {
                Entry ent = cursor.get();
                if (ent.getDn().equals(dn)) continue;
                entries.add(ent);
            }
            cursor.close();
            return entries;
        } catch (Throwable e) {
            return Collections.emptyList();
        }
    }

    private Entry addGroup(Group iamGroup) throws LdapException {
        Entry existingGroup = getExistingGroup(iamGroup);
        if (existingGroup != null) {
            return existingGroup;
        }

        String gid = allocateGroupID(iamGroup.getArn());
        Entry group = new DefaultEntry(directory.getSchemaManager(), directory.getDnFactory().create(String.format(GROUP_FMT, iamGroup.getGroupName())));
        group.put(SchemaConstants.OBJECT_CLASS_AT, "posixGroup", "iamgroup");
        group.put("gidNumber", gid);
        group.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        group.put(SchemaConstants.CN_AT, iamGroup.getGroupName());
        group.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(group);
        return group;
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
        return allocateID();
    }

    private String allocateID() {
        synchronized (ID_LOCK) {
            int lastID;
            String newID;
            try {
                lastID = Integer.parseInt(configEntry.get(ID_GENERATOR).getString());
                newID = String.valueOf(lastID+1);
                directory.getAdminSession().modify(configEntry.getDn(),
                        new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, ID_GENERATOR, newID)
                );
                configEntry.put(ID_GENERATOR, newID);
            } catch (LdapException e) {
                throw new RuntimeException(e);
            }
            return newID;
        }
    }

    private void populateUsersFromIAM() {
        AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);

        try {
            ListUsersResult res = client.listUsers();
            Set<String> allUsers = new HashSet<String>();
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
                        allUsers.add(user.getUserName());
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
            removeDeletedUsers(allUsers);
        } finally {
            client.shutdown();
        }
    }

    private void removeDeletedUsers(Set<String> userNames) {
        Collection<Entry> allUsers = getAllEntries(usersDN, "iamaccount");
        for (Entry user : allUsers) {
            if (!userNames.contains(user.get(SchemaConstants.CN_AT).toString())) {
                try {
                    directory.getAdminSession().delete(user.getDn());
                } catch (LdapException e) {
                    LOG.error("Unable to delete user " + user.getDn());
                }
            }
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
        ent.put("uidNumber", allocateUserID(user.getArn()));
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
        return allocateID();
    }

    public void start() {
        LOG.info("IAMPoller started");
        Runnable poll = new Runnable() {
            @Override
            public void run() {
                pollIAM();
            }
        };
        schedule = Executors.newScheduledThreadPool(1).scheduleAtFixedRate(poll, 10, pollPeriod, TimeUnit.SECONDS);
    }
}
