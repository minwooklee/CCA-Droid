package com.ccadroid.slice;

import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import com.ccadroid.inspect.SlicingCriterion;
import soot.Unit;
import soot.Value;
import soot.jimple.IntConstant;
import soot.jimple.internal.*;

import java.util.ArrayList;
import java.util.HashMap;

import static com.ccadroid.util.soot.SootUnit.*;

public class SliceOptimizer {
    private final CodeInspector codeInspector;
    private final SlicingCriteriaGenerator slicingCriteriaGenerator;
    private ProgramSlicer slicer;

    public SliceOptimizer() {
        codeInspector = CodeInspector.getInstance();
        slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
    }

    public static SliceOptimizer getInstance() {
        return SliceOptimizer.Holder.instance;
    }

    public ArrayList<Unit> getUnreachableUnits(ArrayList<Unit> wholeUnits, ArrayList<Unit> units) {
        HashMap<Value, String> targetValueMap = new HashMap<>();

        return getUnreachableUnits(wholeUnits, units, null, targetValueMap);
    }

    public ArrayList<Unit> getUnreachableUnits(ArrayList<Unit> wholeUnits, ArrayList<Unit> units, String targetSignature, HashMap<Value, String> targetValueMap) {
        int wholeUnitCount = wholeUnits.size();

        ArrayList<Unit> targetUnits = new ArrayList<>();
        for (int i = 0; i < wholeUnitCount; i++) {
            Unit unit = wholeUnits.get(i);
            if (!units.contains(unit)) {
                continue;
            }

            int unitType = getUnitType(unit);
            if ((unitType & INVOKE) == INVOKE) {
                ArrayList<Value> paramValues = getParamValues(unit, unitType);
                if (paramValues.isEmpty()) {
                    continue;
                }

                String unitStr = unit.toString();
                String signature = getSignature(unitStr);
                if (targetSignature == null || !targetSignature.equals(signature)) {
                    continue;
                }

                for (int j = 0; j < paramValues.size(); j++) {
                    Value value = paramValues.get(j);
                    String valueStr = convertToStr(value);
                    targetValueMap.put(IntConstant.v(j), valueStr);
                }
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value leftValue = getLeftValue(unit, unitType);
                Value rightValue = getRightValue(unit, unitType);
                String rightValueStr = convertToStr(rightValue);

                targetValueMap.put(leftValue, rightValueStr);
            } else if (unitType == ASSIGN_VARIABLE_VARIABLE) {
                Value leftValue = getLeftValue(unit, unitType);
                Value rightValue = getRightValue(unit, unitType);

                targetValueMap.put(rightValue, targetValueMap.remove(leftValue));
            } else if (unitType == PARAMETER) {
                String unitStr = unit.toString();
                String paramNum = getParamNum(unitStr, unitType);
                int n = Integer.parseInt(paramNum);
                Value v = IntConstant.v(n);
                if (!targetValueMap.containsKey(v)) {
                    continue;
                }

                Value value = getLeftValue(unit, unitType);
                targetValueMap.put(value, targetValueMap.remove(v));
            } else if (unitType == IF) {
                int result = getIfStatementResult(unit, unitType, targetValueMap);
                if (result == -1) {
                    continue;
                }

                Unit targetUnit1 = getTargetUnit(unit, unitType);
                int targetUnitIndex1 = wholeUnits.indexOf(targetUnit1);
                Unit prevUnit = wholeUnits.get(targetUnitIndex1 - 1);
                int gotoUnitIndex = wholeUnits.indexOf(prevUnit);
                if (result == 1) {
                    for (int j = i + 1; j < gotoUnitIndex; j++) {
                        Unit u = wholeUnits.get(j);
                        targetUnits.add(u);
                    }

                    i = targetUnitIndex1;
                } else {
                    int prevUnitType = getUnitType(prevUnit);
                    Unit targetUnit2 = getTargetUnit(prevUnit, prevUnitType);
                    if (targetUnit2 == null) {
                        continue;
                    }

                    int targetUnitIndex2 = wholeUnits.indexOf(targetUnit2);
                    for (int j = gotoUnitIndex + 1; j <= targetUnitIndex2; j++) {
                        Unit u = wholeUnits.get(j);
                        targetUnits.add(u);
                    }

                    i = targetUnitIndex2;
                }
            }
        }

        return targetUnits;
    }

    public ArrayList<String> getUnreachableUnitStrings(ArrayList<String> ids) {
        if (slicer == null) {
            slicer = ProgramSlicer.getInstance();
        }

        HashMap<Value, String> targetValueMap = new HashMap<>();
        String targetSignature;
        ArrayList<String> targetUnitStrings = new ArrayList<>();

        for (int i = 0; i < ids.size(); i++) {
            String nodeId = ids.get(i);
            SlicingCriterion slicingCriterion = slicingCriteriaGenerator.getSlicingCriterion(nodeId);
            targetSignature = (i == 0) ? slicingCriterion.getTargetSignature() : slicingCriterion.getCallerName();
            String signature = slicingCriterion.getCallerName();
            ArrayList<Unit> wholeUnits = codeInspector.getWholeUnits(signature);
            ArrayList<Unit> units = slicer.getUnits(nodeId);

            ArrayList<Unit> unreachableUnits = getUnreachableUnits(wholeUnits, units, targetSignature, targetValueMap);
            for (Unit u : unreachableUnits) {
                String unitStr = u.toString();
                targetUnitStrings.add(unitStr);
            }
        }

        return targetUnitStrings;
    }

    private int getIfStatementResult(Unit unit, int unitType, HashMap<Value, String> targetValueMap) {
        Value conditionValue = getConditionValue(unit, unitType);
        if (conditionValue == null) {
            return -1;
        }

        AbstractJimpleIntBinopExpr expr = (AbstractJimpleIntBinopExpr) conditionValue;
        Value leftValue = expr.getOp1();
        if (!targetValueMap.containsKey(leftValue)) {
            return -1;
        }

        Value rightValue = expr.getOp2();
        if (!(rightValue instanceof IntConstant) && !targetValueMap.containsKey(rightValue)) {
            return -1;
        }

        int n1 = Integer.parseInt(targetValueMap.get(leftValue));
        int n2 = Integer.parseInt((targetValueMap.containsKey(rightValue) ? targetValueMap.get(rightValue) : convertToStr(rightValue)));

        boolean flag;
        if (conditionValue instanceof JGeExpr) {
            flag = (n1 >= n2);
        } else if (conditionValue instanceof JGtExpr) {
            flag = (n1 > n2);
        } else if (conditionValue instanceof JEqExpr) {
            flag = (n1 == n2);
        } else if (conditionValue instanceof JNeExpr) {
            flag = (n1 != n2);
        } else if (conditionValue instanceof JLtExpr) {
            flag = (n1 < n2);
        } else { // conditionValue instanceof JLeExpr
            flag = (n1 <= n2);
        }

        return flag ? 1 : 0;
    }

    private static class Holder {
        private static final SliceOptimizer instance = new SliceOptimizer();
    }
}