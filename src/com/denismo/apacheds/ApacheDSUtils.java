/*
 * Copyright (c) 2014 Denis Mikhalkin.
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

package com.denismo.apacheds;

import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.AbstractBTreePartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.server.xdbm.IndexEntry;
import org.apache.directory.server.xdbm.ParentIdAndRdn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

/**
 * User: Denis Mikhalkin
 * Date: 30/06/2014
 * Time: 11:12 PM
 */
public class ApacheDSUtils {
    private static final Logger LOG = LoggerFactory.getLogger(ApacheDSUtils.class);

    private DirectoryService service;

    public ApacheDSUtils(DirectoryService service) {
        this.service = service;
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
    public Partition addPartition(String partitionId, String partitionDn, DnFactory dnFactory) throws Exception
    {
        // Create a new partition with the given partition id
        JdbmPartition partition = new JdbmPartition(service.getSchemaManager(), dnFactory);
        partition.setId(partitionId);
        partition.setPartitionPath(new File(service.getInstanceLayout().getPartitionsDirectory(), partitionId).toURI());
        partition.setSuffixDn(new Dn(service.getSchemaManager(), partitionDn));
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
    public void addIndex(Partition partition, String... attrs)
    {
        // Index some attributes on the apache partition
        Set<Index<?,String>> indexedAttributes = new HashSet<Index<?,String>>();

        for ( String attribute : attrs )
        {
            indexedAttributes.add( new JdbmIndex( attribute, false ) );
        }

        ( ( JdbmPartition ) partition ).setIndexedAttributes( indexedAttributes );
    }

    boolean exists(String s) throws LdapException {
        return service.getAdminSession().exists(s);
    }
    public boolean exists(Dn dnIAM) {
        try {
            return service.getAdminSession().exists(dnIAM);
        } catch (LdapException e) {
            return false;
        }
    }

    public void loadLdif(String s) throws LdapException {
        if (getClass().getClassLoader().getResourceAsStream(s) == null) {
            s = new File("E:\\WS\\ApacheDS_AWSIAM\\dist\\apacheds\\" + s).getAbsolutePath();
        }
        LdifFileLoader loader = new LdifFileLoader(service.getAdminSession(), s);
        loader.execute();
    }
    public void dumpIndex(Partition part) {
        if (!LOG.isDebugEnabled()) return;

        Index<ParentIdAndRdn, String> rdnIdx = ((AbstractBTreePartition)part).getRdnIndex();
        LOG.debug("Dumping index " + rdnIdx);
        try {
            Cursor<IndexEntry<ParentIdAndRdn, String>> cursor = rdnIdx.forwardCursor();
            while (cursor.next()) {
                IndexEntry<ParentIdAndRdn, String> entry = cursor.get();
                LOG.debug("  " + entry.getKey());
            }
        } catch (LdapException e) {
            e.printStackTrace();
        } catch (CursorException e) {
            e.printStackTrace();
        }
    }


}
