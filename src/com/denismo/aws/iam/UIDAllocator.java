package com.denismo.aws.iam;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.services.dynamodb.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodb.model.*;
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
    private AWSCredentials credentials;
    private String table;

    public UIDAllocator(AWSCredentials credentials, String space) {
        this.credentials = credentials;
        this.table = "IAM" + space;
    }
    public String allocateUID(String name) {
        AmazonDynamoDBClient client = new AmazonDynamoDBClient(credentials);
        client.setEndpoint("dynamodb.ap-southeast-2.amazonaws.com");

        GetItemResult getItem = null;
        getItem = client.getItem(new GetItemRequest().withTableName(table).withKey(new Key(new AttributeValue().withS(name))).withAttributesToGet("uidNumber"));
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
