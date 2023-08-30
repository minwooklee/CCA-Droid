package com.ccadroid.util.graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;

import java.util.ArrayList;

public class CallGraph extends BaseGraph {

    public CallGraph() {
        int hashCode = this.hashCode();
        String id = String.valueOf(hashCode);
        graph = new SingleGraph(id);
        graph.setAutoCreate(false);
    }

    public Node addNode(String hashCode, String label) {
        return super.addNode(hashCode, label);
    }

    public void addEdge(Node node1, Node node2, EdgeType type) {
        super.addEdge(node1, node2, type);
    }

    public Node getNode(String id) {
        return super.getNode(id);
    }

    public Edge getEdge(Node node1, Node node2, EdgeType type) {
        return super.getEdge(node1, node2, type);
    }

    public ArrayList<ArrayList<String>> getListOfIds(String id, boolean isUpper) {
        return super.getListOfIds(id, isUpper);
    }
}