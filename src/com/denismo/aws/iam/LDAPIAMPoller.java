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
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.*;
import com.denismo.apacheds.ApacheDSUtils;
import com.denismo.apacheds.Runner;
import com.denismo.apacheds.auth.AWSIAMAuthenticator;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.*;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.normalizers.ConcreteNameComponentNormalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.NameComponentNormalizer;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.normalization.FilterNormalizingVisitor;
import org.apache.commons.lang.text.StrTokenizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.lang.ProcessBuilder;

/**
 * User: Denis Mikhalkin
 * Date: 30/03/13
 * Time: 10:53 PM
 */
public class LDAPIAMPoller {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPIAMPoller.class);
    private static final Object ID_LOCK = new Object();
    public static final String ID_GENERATOR = "ads-dsSyncPeriodMillis";
    public static final String MEMBER_OF = "memberOf";

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
    private ApacheDSUtils utils;
    private Runner runner;
    private String externalPollerCommand;

    public LDAPIAMPoller(DirectoryService directoryService) throws LdapException {
        this.directory = directoryService;

        credentials = new DefaultAWSCredentialsProviderChain();
        try {
            credentials.getCredentials(); // throws
        } catch (AmazonClientException ex) {
            LOG.error("AWS credentials error", ex);
            throw new LdapException("Unable to initialze AWS poller - cannot retrieve valid credentials");
        }
        utils = new ApacheDSUtils(directory);
        runner = new Runner(directory);
        LOG.info("IAMPoller created");
    }

    private void createStructure() throws Exception {
        if (!firstRun) return;
        firstRun = false;
        try {
            runner.createStructure();
            readConfig();
        } catch (Exception e) {
            LOG.error("Exception preparing structure", e);
            schedule.cancel(false);
            throw new RuntimeException("Unable to initialize poller");
        }
    }

    private void readConfig() {
        try {
            Dn configDn = directory.getDnFactory().create("cn=config,ads-authenticatorid=awsiamauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config");
            if (!utils.exists(configDn)) {
                configEntry = directory.newEntry(configDn);
                configEntry.put("objectClass", "iamauthenticatorconfig", "top");
                configEntry.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
                configEntry.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
                configEntry.put("cn", "config");
                configEntry.put(ID_GENERATOR, "1000");
                directory.getAdminSession().add(configEntry);
            } else {
                LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                        configDn,
                        SchemaConstants.ALL_USER_ATTRIBUTES, SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES);
                configEntry = directory.getPartitionNexus().lookup(lookupContext);
            }

            AWSIAMAuthenticator.Config config = AWSIAMAuthenticator.getConfig();
            rootDN = config.rootDN;
            pollPeriod = config.pollPeriod;

            externalPollerCommand = config.externalPollerCommand;

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

        LOG.debug("Deleting " + dns.size() + " items from under " + dnStr);
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

    private int runExternalPoller() throws IOException, InterruptedException {
        LOG.info("Running external poller command: " + externalPollerCommand);
        Process p = new ProcessBuilder("/bin/bash", "-c", this.externalPollerCommand).start();
        int returnCode = p.waitFor();
        LOG.info(String.format("External Poller complete: retcode=%d", returnCode));
        return returnCode;
    }

    private void pollIAM() {
        if (!directory.isStarted()) return;

        LOG.debug("*** Updating accounts from IAM");
        try {
            createStructure();
            populateGroupsFromIAM();
            populateUsersFromIAM();

//            populateRolesFromIAM();
            LOG.debug("*** IAM account update finished");

            // add external poller here
            if (this.externalPollerCommand != null) {
                runExternalPoller();
            }


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
                        LOG.debug("Added role " + role.getRoleName() + " at " + rolesDN);
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

    private Entry getOrCreateRoleGroup(Role role) throws Exception {
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
                        LOG.debug("Added group " + group.getGroupName() + " at " + groupsDN);
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
            try {
                if (!groupNames.contains(group.get(SchemaConstants.CN_AT).getString())) {
                    LOG.debug("Deleting non-existant group " + group.get(SchemaConstants.CN_AT).getString());
                    directory.getAdminSession().delete(group.getDn());
                }
            } catch (LdapException e) {
                LOG.error("Unable to delete group " + group.getDn());
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

    private Entry addGroup(Group iamGroup) throws Exception {
        LOG.debug("Adding group " + iamGroup.getGroupName());
        Entry existingGroup = getExistingGroup(iamGroup);
        if (existingGroup != null) {
            LOG.debug("Group exists: " + iamGroup.getGroupName());
            return existingGroup;
        }

        String gid = allocateGroupID(iamGroup.getArn());
        Dn groupDn = directory.getDnFactory().create(String.format(GROUP_FMT, iamGroup.getGroupName()));
        LOG.debug("New group dn: " + groupDn);
        Entry group = new DefaultEntry(directory.getSchemaManager(), groupDn);
        group.put(SchemaConstants.OBJECT_CLASS_AT, "posixGroup", "iamgroup", "top");
        group.put("gidNumber", gid);
        group.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        group.put(SchemaConstants.CN_AT, iamGroup.getGroupName());
        group.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        add(group);
        return group;
    }
    private Entry getExistingGroup(Group iamGroup) throws Exception {
        Dn dn = directory.getDnFactory().create(String.format(GROUP_FMT, iamGroup.getGroupName()));

        LookupOperationContext lookupContext = new LookupOperationContext( directory.getAdminSession(),
                dn,
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
        directory.getAdminSession().add(entry);
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
                        addUser(user, getUserAccessKey(client, user), groupEntry, groups);
                        updateGroups(groups, user);
                        allUsers.add(user.getUserName());
                        LOG.debug("Added user " + user.getUserName());
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
        Set<String> toBeDeleted = new HashSet<String>();
        Collection<Entry> allUsers = getAllEntries(usersDN, "iamaccount");
        for (Entry user : allUsers) {
            try {
                String userName = user.get(SchemaConstants.CN_AT).getString();
                if (!userNames.contains(userName)) {
                    toBeDeleted.add(userName);
                    LOG.debug("Deleting non-existing user " + user.get(SchemaConstants.CN_AT));
                    directory.getAdminSession().delete(user.getDn());
                }
            } catch (LdapException e) {
                LOG.error("Unable to delete user " + user.getDn());
            }
        }
        Collection<Entry> allGroups = getAllEntries(groupsDN, "iamgroup");
        for (Entry group : allGroups) {
            try {
                List<Modification> deletions = new ArrayList<Modification>();
                for (String userUid: toBeDeleted) {
                    if (group.contains("memberUid", userUid)) {
                        deletions.add(new DefaultModification(ModificationOperation.REMOVE_ATTRIBUTE, "memberUid", userUid));
                    }
                }
                if (!deletions.isEmpty()) {
                    LOG.debug("Deleting " + deletions + " from " + group.getDn());
                    directory.getAdminSession().modify(group.getDn(), deletions);
                }
            } catch (LdapException e) {
                LOG.error("Unable to delete users from group " + group.getDn());
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

    private void addUser(User user, String accessKey, Entry group, Collection<Group> otherGroups) throws LdapException {
        if (accessKey == null) {
            if (AWSIAMAuthenticator.getConfig().isSecretKeyLogin()) {
                LOG.debug("User " + user.getUserName() + " has no active access keys");
                return;
            } else {
                accessKey = "";
            }
        }
        Entry existingUser = getExistingUser(user);
        if (existingUser != null) {
            directory.getAdminSession().modify(existingUser.getDn(),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "accessKey", accessKey),
                    new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, "gidNumber", group.get("gidNumber").getString())
            );
            // TODO If gidNumber changed for user, shouldn't groups memberUid list be updated?
            updateUserMemberOf(existingUser, otherGroups);
            return;
        }

        DefaultEntry ent = new DefaultEntry(directory.getSchemaManager(), directory.getDnFactory().create(String.format(USER_FMT, user.getUserName())));
        ent.put(SchemaConstants.OBJECT_CLASS_AT, "posixAccount", "shadowAccount", "iamaccount", "extensibleObject");
        ent.put("accessKey", accessKey);
        ent.put("uid", user.getUserName());
        ent.put(SchemaConstants.ENTRY_CSN_AT, directory.getCSN().toString());
        ent.put(SchemaConstants.ENTRY_UUID_AT, UUID.randomUUID().toString());
        ent.put("cn", user.getUserName());
        ent.put("uidNumber", allocateUserID(user.getArn()));
        if (group != null) {
            ent.put("gidNumber", group.get("gidNumber").getString());
        } else {
            ent.put("gidNumber", "1001");
        }
        ent.put("shadowLastChange", "10877");
        ent.put("shadowExpire", "-1");
        ent.put("shadowInactive", "-1");
        ent.put("shadowFlag", "0");
        ent.put("shadowWarning", "7");
        ent.put("shadowMin", "0");
        ent.put("shadowMax", "999999");
        ent.put("loginshell", "/bin/bash");
        ent.put("homedirectory", "/home/" + user.getUserName());
        ent.put("accountNumber", getAccountNumber(user.getArn()));

        setMemberOf(ent, otherGroups);

        add(ent);
    }

    private void updateUserMemberOf(Entry existingUser, Collection<Group> otherGroups) {
        LOG.debug("Updating memberOf of " + existingUser.getDn());
        try {
            Set<String> existingGroups = new HashSet<String>();
            Attribute memberOf = existingUser.get(MEMBER_OF);
            if (memberOf != null) {
                for (Value value : memberOf) {
                    existingGroups.add(value.getString());
                }
            }
            LOG.debug("Existing memberOf groups; " + existingGroups);
            List<Modification> modifications = new ArrayList<Modification>();
            for (Group group : otherGroups) {
                try {
                    // Skip if it is already present
                    Entry ldapGroup = getExistingGroup(group);
                    // Add new
                    if (ldapGroup != null) {
                        if (existingGroups.remove(ldapGroup.getDn().toString())) {
                            continue;
                        }
                        modifications.add(new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, MEMBER_OF,
                                ldapGroup.getDn().toString()));
                    }
                } catch (Exception e) {
                    LOG.error("Unable to update groups for user " + existingUser.getDn() + " while looking at " + group, e);
                }
            }
            // All remaining group names in existingGroups are absent in IAM so they need to be deleted
            for (String group : existingGroups) {
                modifications.add(new DefaultModification(ModificationOperation.REMOVE_ATTRIBUTE, MEMBER_OF, group));
            }
            LOG.debug("Executing modifications: " + modifications);
            directory.getAdminSession().modify(existingUser.getDn(), modifications);
        } catch (LdapException e) {
            LOG.error("Unable to modify memberOf for user " + existingUser.getDn(), e);
        }
    }

    private void setMemberOf(DefaultEntry userEntry, Collection<Group> otherGroups) {
        for (Group group : otherGroups) {
            try {
                Entry ldapGroup = getExistingGroup(group);
                if (ldapGroup != null) {
                    userEntry.add(MEMBER_OF, ldapGroup.getDn().toString());
                }
            } catch (Exception e) {
                LOG.error("Unable to update groups for user " + userEntry.getDn(), e);
            }
        }
    }

    /**
     * Updates the list of users in each specified group, to include the new user.
     * @param groups the list of groups to update
     * @param user the discovered user
     */

    private void updateGroups(Collection<Group> groups, User user) {
        Set<String> groupNames = new HashSet<String>();
        for (Group group : groups) {
            groupNames.add(group.getGroupName());
        }
        Collection<Entry> allGroups = getAllEntries(groupsDN, "iamgroup");
        String userUid = user.getUserName();
        LOG.debug("Updating groups for " + userUid);
        for (Entry group : allGroups) {
            LOG.debug("Looking at group " + group.getDn());
            try {
                List<Modification> modifications = new ArrayList<Modification>();
                if (groupNames.contains(group.get(SchemaConstants.CN_AT).getString())) {
                    if (!group.contains("memberUid", userUid)) {
                        modifications.add(new DefaultModification(ModificationOperation.ADD_ATTRIBUTE, "memberUid", userUid));
                    }
                } else {
                    if (group.contains("memberUid", userUid)) {
                        modifications.add(new DefaultModification(ModificationOperation.REMOVE_ATTRIBUTE, "memberUid", userUid));
                    }
                }
                if (!modifications.isEmpty()) {
                    LOG.debug("Will modify group with " + modifications);
                    directory.getAdminSession().modify(group.getDn(), modifications);
                }
            } catch (LdapException e) {
                LOG.error("Unable to update users in group " + group.getDn(), e);
            }
        }
    }

    private static final Pattern ACCOUNT_PATTERN = Pattern.compile("arn:aws:iam::(\\d+):user/.*");
    private String getAccountNumber(String arn) {
        Matcher result = ACCOUNT_PATTERN.matcher(arn);
        if (result.matches()) {
            return result.group(1);
        }
        throw new RuntimeException("Unable to identify account number for " + arn);
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
