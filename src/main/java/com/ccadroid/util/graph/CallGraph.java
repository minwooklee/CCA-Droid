package com.ccadroid.util.graph;

import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;

import java.util.ArrayList;
import java.util.List;

public class CallGraph extends BaseGraph {
    public static final String LEVEL = "level";

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

    public List<Edge> getEdges(Node node) {
        return super.getEdges(node);
    }

    public Edge getEdge(Node node1, Node node2, EdgeType type) {
        return super.getEdge(node1, node2, type);
    }

    public ArrayList<ArrayList<String>> getListOfIds(String id, boolean isUpper) {
        return super.getListOfIds(id, isUpper);
    }
}