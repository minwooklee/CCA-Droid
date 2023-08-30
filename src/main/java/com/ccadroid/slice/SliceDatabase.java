package com.ccadroid.slice;

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
        MongoClient client = MongoClients.create("mongodb://localhost:27017");
        MongoDatabase database = client.getDatabase("CCA-Droid");
        collection = database.getCollection(packageName);
    }

    public void insert(String nodeId, String topId, String callerName, String targetSignature, int startUnitIndex, ArrayList<String> targetVariables, ArrayList<Document> slice) {
        Document document = new Document();
        document.append(NODE_ID, nodeId);
        document.append(GROUP_ID, topId);
        document.append(CALLER_NAME, callerName);
        document.append(TARGET_SIGNATURE, targetSignature);
        document.append(START_UNIT_INDEX, startUnitIndex);
        document.append(TARGET_VARIABLES, targetVariables);
        document.append(CONTENT, slice);

        collection.insertOne(document);
    }

    public void insert(String id, String targetSignature, ArrayList<String> targetParamNums, ArrayList<Document> slice) {
        Document document = new Document();
        document.append(GROUP_ID, id);
        document.append(TARGET_SIGNATURE, targetSignature);
        document.append(TARGET_PARAM_NUMS, targetParamNums);
        document.append(CONTENT, slice);

        collection.insertOne(document);
    }

    public FindIterable<Document> selectAll(String json) {
        Document query = Document.parse(json);

        return collection.find(query);
    }

    public int selectCount(String json) {
        Document query = Document.parse(json);

        return (int) collection.countDocuments(query);
    }

    public ArrayList<Document> getSlice(String id) {
        FindIterable<Document> result = selectAll("{'" + NODE_ID + "': '" + id + "'}");
        Document document = result.first();
        if (document == null) {
            return new ArrayList<>();
        }

        Object o = document.get(CONTENT);
        if (!(o instanceof ArrayList)) {
            return new ArrayList<>();
        }

        return (ArrayList<Document>) document.getList(CONTENT, Document.class);
    }

    private static class Holder {
        private static final SliceDatabase instance = new SliceDatabase();
    }
}