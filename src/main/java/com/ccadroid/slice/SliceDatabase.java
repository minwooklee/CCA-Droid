package com.ccadroid.slice;

import com.mongodb.MongoTimeoutException;
import com.mongodb.client.*;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import org.bson.conversions.Bson;

import java.util.ArrayList;

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

    public boolean isSliceExist(String hashCode, boolean isMerged) {
        Document result = null;

        Bson filter;
        if (isMerged) {
            Bson filter1 = Filters.eq("hashCode", hashCode);
            Bson filter2 = Filters.exists("merged");
            filter = Filters.and(filter1, filter2);
        } else {
            filter = Filters.eq("hashCode", hashCode);
        }

        try {
            FindIterable<Document> iterable = collection.find(filter);
            result = iterable.first();
        } catch (MongoTimeoutException ignored) {
            System.out.println("[*] ERROR: Check please MongoDB status!");
            System.exit(1);
        }

        return result != null;
    }

    public void insert(String hashCode, String callerName, String targetStatement, int startUnitIndex, ArrayList<String> targetVariables, ArrayList<Document> slice) {
        Document document = new Document();
        document.append("hashCode", hashCode);
        document.append("callerName", callerName);
        document.append("targetStatement", targetStatement);
        document.append("startUnitIndex", startUnitIndex);
        document.append("targetVariables", targetVariables);
        document.append("slice", slice);

        collection.insertOne(document);
    }

    public void insert(String hashCode, ArrayList<Document> slice) {
        Document document = new Document();
        document.put("hashCode", hashCode);
        document.put("merged", slice);

        collection.insertOne(document);
    }

    public ArrayList<Document> getSlice(String hashCode) {
        Bson filter = Filters.eq("hashCode", hashCode);
        FindIterable<Document> iterable = collection.find(filter);
        Document document = iterable.first();
        if (document == null) {
            return new ArrayList<>();
        }

        return (ArrayList<Document>) document.get("slice");
    }

    private static class Holder {
        private static final SliceDatabase instance = new SliceDatabase();
    }
}