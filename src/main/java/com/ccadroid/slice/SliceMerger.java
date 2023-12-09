package com.ccadroid.slice;

import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.graph.BaseGraph;
import com.ccadroid.util.graph.CallGraph;
import org.bson.Document;
import org.graphstream.graph.Node;
import soot.Unit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.graph.CallGraph.LEVEL;
import static com.ccadroid.util.soot.SootUnit.PARAMETER;
import static com.ccadroid.util.soot.SootUnit.convertToStrings;

public class SliceMerger {
    private final SliceDatabase sliceDatabase;
    private final SliceOptimizer sliceOptimizer;
    private final CallGraph callGraph;

    public SliceMerger() {
        sliceDatabase = SliceDatabase.getInstance();
        sliceOptimizer = SliceOptimizer.getInstance();

        callGraph = new CallGraph();
    }

    public static SliceMerger getInstance() {
        return SliceMerger.Holder.instance;
    }

    public Node addNode(String hashCode, String label, String groupId, int level) {
        Node node = callGraph.addNode(hashCode, label);
        node.setAttribute(GROUP_ID, groupId);
        node.setAttribute(LEVEL, level);

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
        String query1 = "{'" + NODE_ID + "': {$exists: false}, '" + GROUP_ID + "': '" + leafId + "'}";
        Document mergedSlice = sliceDatabase.findSlice(query1);
        if (mergedSlice != null) {
            return;
        }

        String targetStatement = slicingCriterion.getTargetStatement();
        ArrayList<String> targetParamNumbers = slicingCriterion.getTargetParamNumbers();
        ArrayList<String> targetVariables = convertToStrings(slicingCriterion.getTargetVariables());

        ArrayList<ArrayList<String>> listOfIds = callGraph.getListOfIds(leafId, true);
        for (ArrayList<String> ids : listOfIds) {
            ArrayList<Document> slices = new ArrayList<>();
            ArrayList<Document> mergedContent = new ArrayList<>();

            for (String id : ids) {
                String query2 = "{'" + NODE_ID + "': '" + id + "'}";
                Document slice = sliceDatabase.findSlice(query2);
                if (slice == null) {
                    continue;
                }

                slices.add(slice);
                List<Document> content = slice.getList(CONTENT, Document.class);
                mergedContent.addAll(content);
            }

            if (mergedContent.isEmpty()) {
                continue;
            }

            if (isStartingParameter(mergedContent)) {
                continue;
            }

            if (ids.size() > 1) {
                ArrayList<Document> unreachables = sliceOptimizer.getUnreachableLines(slices);
                mergedContent.removeAll(unreachables);

                HashMap<Unit, Unit> updates = sliceOptimizer.getInterpretedUnits(slices);
                sliceOptimizer.updateLines(updates, mergedContent);
            }

            sliceDatabase.insert(leafId, targetStatement, targetParamNumbers, targetVariables, mergedContent);
        }
    }

    private boolean isStartingParameter(ArrayList<Document> slice) {
        Document line = slice.get(0);
        int unitType = line.getInteger(UNIT_TYPE);

        return (unitType == PARAMETER);
    }

    private static class Holder {
        private static final SliceMerger instance = new SliceMerger();
    }
}