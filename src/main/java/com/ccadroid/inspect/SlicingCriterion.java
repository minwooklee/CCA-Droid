package com.ccadroid.inspect;

import soot.ValueBox;

import java.util.ArrayList;
import java.util.HashMap;

public class SlicingCriterion {
    private String callerName;
    private String targetSignature;
    private int targetUnitIndex;
    private ArrayList<String> targetParamNums;
    private HashMap<String, ValueBox> targetVariableMap;

    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    public String getTargetSignature() {
        return targetSignature;
    }

    public void setTargetSignature(String targetSignature) {
        this.targetSignature = targetSignature;
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
        return callerName.hashCode() + targetSignature.hashCode() + targetUnitIndex;
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + callerName + ", targetSignature=" + targetSignature + ", targetVariableMap=" + targetVariableMap + "}";
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