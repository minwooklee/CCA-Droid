package com.ccadroid.model;

import org.graphstream.graph.Node;
import soot.Unit;
import soot.ValueBox;

import java.util.ArrayList;
import java.util.HashMap;

public class SlicingCriterion {
    private Node caller;
    private String targetStatement;
    private ArrayList<String> targetParamNums;
    private int targetUnitIndex;
    private HashMap<String, ValueBox> targetVariableMap;
    private ArrayList<Unit> wholeUnits;

    public Node getCaller() {
        return caller;
    }

    public void setCaller(Node caller) {
        this.caller = caller;
    }

    public String getTargetStatement() {
        return targetStatement;
    }

    public void setTargetStatement(String targetStatement) {
        this.targetStatement = targetStatement;
    }

    public ArrayList<String> getTargetParamNums() {
        return targetParamNums;
    }

    public void setTargetParamNums(ArrayList<String> targetParamNums) {
        this.targetParamNums = targetParamNums;
    }

    public int getTargetUnitIndex() {
        return targetUnitIndex;
    }

    public void setTargetUnitIndex(int targetUnitIndex) {
        this.targetUnitIndex = targetUnitIndex;
    }

    public HashMap<String, ValueBox> getTargetVariableMap() {
        return targetVariableMap;
    }

    public void setTargetVariableMap(HashMap<String, ValueBox> targetVariableMap) {
        this.targetVariableMap = targetVariableMap;
    }

    public ArrayList<Unit> getWholeUnits() {
        return wholeUnits;
    }

    public void setWholeUnits(ArrayList<Unit> wholeUnits) {
        this.wholeUnits = wholeUnits;
    }

    @Override
    public int hashCode() {
        return wholeUnits.hashCode() + targetStatement.hashCode() + ((targetVariableMap == null) ? 0 : targetVariableMap.hashCode()) + targetUnitIndex;
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + caller + ", targetStatement=" + targetStatement + ", targetVariableMap=" + targetVariableMap + "}";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj == null || getClass() != obj.getClass()) {
            return false;
        } else {
            return hashCode() == (obj.hashCode());
        }
    }

    @Override
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException ignored) {
            return null;
        }
    }
}