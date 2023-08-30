package com.ccadroid.slice;

import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.graph.BaseGraph;
import com.ccadroid.util.graph.CallGraph;
import org.bson.Document;
import org.graphstream.graph.Node;

import java.util.ArrayList;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.PARAMETER;

public class SliceMerger {
    private final CallGraph callGraph;
    private final SliceDatabase sliceDatabase;

    public SliceMerger() {
        callGraph = new CallGraph();
        sliceDatabase = SliceDatabase.getInstance();
    }

    public static SliceMerger getInstance() {
        return SliceMerger.Holder.instance;
    }

    public Node addNode(String hashCode, String label, String topId, int level) {
        Node node = callGraph.addNode(hashCode, label);
        node.setAttribute(GROUP_ID, topId);
        node.setAttribute("level", level);

        return node;
    }

    public void addEdge(Node node1, Node node2, BaseGraph.EdgeType type) {
        callGraph.addEdge(node1, node2, type);
    }

    public Node getNode(String id) {
        return callGraph.getNode(id);
    }

    public void mergeSlices(SlicingCriterion slicingCriterion) {
        String leafId = String.valueOf(slicingCriterion.hashCode());
        if (sliceDatabase.selectCount("{'" + NODE_ID + "': {$exists: false}, '" + GROUP_ID + "': '" + leafId + "'}") > 0) {
            return;
        }

        String targetSignature = slicingCriterion.getTargetSignature();
        ArrayList<String> targetParamNums = slicingCriterion.getTargetParamNums();
        ArrayList<ArrayList<String>> listOfIds = callGraph.getListOfIds(leafId, true);
        for (ArrayList<String> ids : listOfIds) {
            ArrayList<Document> slice = new ArrayList<>();
            for (String id : ids) {
                ArrayList<Document> tempSlice = sliceDatabase.getSlice(id);
                slice.addAll(tempSlice);
            }

            if (slice.isEmpty()) {
                continue;
            }

            if (isStartingParameter(slice)) {
                continue;
            }

            sliceDatabase.insert(leafId, targetSignature, targetParamNums, slice);
        }
    }

    private boolean isStartingParameter(ArrayList<Document> slice) {
        Document topDoc = slice.get(0);
        int topUnitType = topDoc.getInteger(UNIT_TYPE);

        return (topUnitType == PARAMETER);
    }

    private static class Holder {
        private static final SliceMerger instance = new SliceMerger();
    }
}