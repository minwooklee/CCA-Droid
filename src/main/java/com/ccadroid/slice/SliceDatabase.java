package com.ccadroid.slice;

import com.ccadroid.util.Configuration;
import com.mongodb.client.*;
import org.bson.Document;

import java.util.ArrayList;

import static com.ccadroid.slice.SliceConstants.*;

public class SliceDatabase {
    private MongoCollection<Document> collection;

    public static SliceDatabase getInstance() {
        return SliceDatabase.Holder.instance;
    }

    public void initialize(String packageName) {
        String uri = Configuration.getProperty("mongo.Uri");
        String databaseName = Configuration.getProperty("mongo.databaseName");
        MongoClient client = MongoClients.create(uri);
        MongoDatabase database = client.getDatabase(databaseName);
        collection = database.getCollection(packageName);
    }

    public void insert(String nodeId, String groupId, String callerName, String targetStatement, int startUnitIndex, ArrayList<String> targetParamNumbers, ArrayList<String> targetVariables, ArrayList<Document> content) {
        Document document = new Document();
        document.append(NODE_ID, nodeId);
        document.append(GROUP_ID, groupId);
        document.append(CALLER_NAME, callerName);
        document.append(TARGET_STATEMENT, targetStatement);
        document.append(TARGET_PARAM_NUMBERS, targetParamNumbers);
        document.append(START_UNIT_INDEX, startUnitIndex);
        document.append(TARGET_VARIABLES, targetVariables);
        document.append(CONTENT, content);

        collection.insertOne(document);
    }

    public void insert(String id, String targetStatement, ArrayList<String> targetParamNumbers, ArrayList<String> targetVariables, ArrayList<Document> content) {
        Document document = new Document();
        document.append(GROUP_ID, id);
        document.append(TARGET_STATEMENT, targetStatement);
        document.append(TARGET_PARAM_NUMBERS, targetParamNumbers);
        document.append(TARGET_VARIABLES, targetVariables);
        document.append(CONTENT, content);

        collection.insertOne(document);
    }

    public FindIterable<Document> selectAll(String query) {
        Document filter = Document.parse(query);

        return collection.find(filter);
    }

    public Document findSlice(String query) {
        FindIterable<Document> result = selectAll(query);
        if (result == null) {
            return null;
        }

        return result.first();
    }

    private static class Holder {
        private static final SliceDatabase instance = new SliceDatabase();
    }
}