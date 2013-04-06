package com.denismo.aws.iam;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodb.model.*;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * User: Denis Mikhalkin
 * Date: 28/03/13
 * Time: 9:15 PM
 */
public class UIDAllocator {
    private static final Logger LOG = LoggerFactory.getLogger(UIDAllocator.class);
    private String table;
    private final AmazonDynamoDBClient client;

    public UIDAllocator(AWSCredentials credentials, String space) throws LdapException {
        this.table = "IAM" + space;
        client = new AmazonDynamoDBClient(credentials);
        client.setEndpoint("dynamodb.ap-southeast-2.amazonaws.com");
        createTable();
    }

    private void createTable() throws LdapException {
        CreateTableResult res = null;
        try {
            res = client.createTable(new CreateTableRequest(table,
                    new KeySchema(new KeySchemaElement().withAttributeName("Name").withAttributeType(ScalarAttributeType.S))).
                    withProvisionedThroughput(new ProvisionedThroughput().withReadCapacityUnits(5L).withWriteCapacityUnits(5L)));
        } catch (ResourceInUseException ri) {
            // Table exists
            return;
        } catch (AmazonClientException e) {
            LOG.error("Exception creating table " + table, e);
            throw new LdapException(e);
        }
        if (TableStatus.ACTIVE.toString().equals(res.getTableDescription().getTableStatus())) {
            return;
        }
        int i = 0;
        boolean active = false;
        do {
            DescribeTableResult dres = client.describeTable(new DescribeTableRequest().withTableName(table));
            if (TableStatus.ACTIVE.toString().equals(dres.getTable().getTableStatus())) {
                active = true;
                break;
            }
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                break;
            }
        } while (i < 20);
        if (!active) {
            throw new LdapException("Unable to initialize the AWS DynamoDB table " + table);
        }
    }

    public String allocateUID(String name) {
        GetItemResult getItem = client.getItem(new GetItemRequest().withTableName(table).withKey(new Key(new AttributeValue().withS(name))).withAttributesToGet("uidNumber"));
        if (getItem.getItem() == null) {
            String counter = getNextID(client);
            LOG.info("Name " + name + " assigned ID " + counter);
            Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
            item.put("Name", new AttributeValue().withS(name));
            item.put("uidNumber", new AttributeValue().withN(counter));
            try {
                client.putItem(new PutItemRequest().withTableName(table).withItem(item).withExpected(Collections.singletonMap("Name", new ExpectedAttributeValue(false))));
                return counter;
            } catch (ConditionalCheckFailedException ccf) {
                counter = client.getItem(new GetItemRequest().withTableName(table).withKey(new Key(new AttributeValue().withS(name))).withAttributesToGet("uidNumber"))
                        .getItem().get("uidNumber").getN();
                LOG.info("Name " + name + " has ID " + counter);
                return counter;
            }
        } else {
            String counter = getItem.getItem().get("uidNumber").getN();
            LOG.info("Name " + name + " has ID " + counter);
            return counter;
        }
    }

    private String getNextID(AmazonDynamoDBClient client) {
        Map<String, AttributeValue> item = new HashMap<String, AttributeValue>();
        item.put("Name", new AttributeValue().withS("GlobalCounter"));
        item.put("Value", new AttributeValue().withN("1001"));
        try {
            client.putItem(new PutItemRequest().withTableName(table).withItem(item).
                    withExpected(Collections.singletonMap("Name", new ExpectedAttributeValue(false))));
            return "1001";
        } catch (ConditionalCheckFailedException e) {
            UpdateItemResult updated = client.updateItem(new UpdateItemRequest().withTableName(table).withKey(new Key(new AttributeValue("GlobalCounter"))).
                    withAttributeUpdates(Collections.singletonMap("Value", new AttributeValueUpdate(new AttributeValue().withN("1"), AttributeAction.ADD))).
                    withReturnValues(ReturnValue.UPDATED_NEW));
            return updated.getAttributes().get("Value").getN();
        }
    }
}
