package com.ccadroid.common.model;

import soot.ValueBox;

import java.util.ArrayList;
import java.util.HashMap;

public class SlicingCriterion {
    private String callerName;
    private String targetStatement;
    private int targetUnitIndex;
    private ArrayList<String> targetParamNums;
    private HashMap<String, ValueBox> targetVariableMap;

    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    public String getTargetStatement() {
        return targetStatement;
    }

    public void setTargetStatement(String targetStatement) {
        this.targetStatement = targetStatement;
    }

    public int getTargetUnitIndex() {
        return targetUnitIndex;
    }

    public void setTargetUnitIndex(int targetUnitIndex) {
        this.targetUnitIndex = targetUnitIndex;
    }

    public ArrayList<String> getTargetParamNums() {
        return targetParamNums;
    }

    public void setTargetParamNums(ArrayList<String> targetParamNums) {
        this.targetParamNums = targetParamNums;
    }

    public HashMap<String, ValueBox> getTargetVariableMap() {
        return targetVariableMap;
    }

    public void setTargetVariableMap(HashMap<String, ValueBox> targetVariableMap) {
        this.targetVariableMap = targetVariableMap;
    }

    @Override
    public int hashCode() {
        return targetStatement.hashCode() + targetUnitIndex + ((targetVariableMap == null) ? 0 : targetVariableMap.hashCode());
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + callerName + ", targetStatement=" + targetStatement + ", targetVariableMap=" + targetVariableMap + "}";
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