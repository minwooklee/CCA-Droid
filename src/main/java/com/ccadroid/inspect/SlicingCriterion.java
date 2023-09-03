package com.ccadroid.inspect;

import soot.Value;

import java.util.ArrayList;
import java.util.HashSet;

public class SlicingCriterion {
    private String callerName;
    private String targetSignature;
    private int targetUnitIndex;
    private ArrayList<String> targetParamNums;
    private HashSet<Value> targetVariables;

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

    public HashSet<Value> getTargetVariables() {
        return targetVariables;
    }

    public void setTargetVariables(HashSet<Value> targetVariables) {
        this.targetVariables = targetVariables;
    }

    @Override
    public int hashCode() {
        return callerName.hashCode() + targetSignature.hashCode() + targetUnitIndex;
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + callerName + ", targetSignature=" + targetSignature + ", targetVariables=" + targetVariables + "}";
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