package com.ccadroid.slice;

import org.bson.Document;
import soot.Unit;
import soot.Value;
import soot.jimple.StringConstant;
import soot.jimple.internal.JAssignStmt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class SliceInterpreter {
    private final HashMap<Value, Unit> valueMap;

    protected SliceInterpreter() {
        valueMap = new HashMap<>();
    }

    public static SliceInterpreter getInstance() {
        return SliceInterpreter.Holder.instance;
    }

    public void interpret(ArrayList<Unit> units, ArrayList<Document> slice) {
        Iterator<Unit> unitIter = new ArrayList<>(units).iterator();
        Iterator<Document> sliceIter = new ArrayList<>(slice).iterator();

        while (unitIter.hasNext() && sliceIter.hasNext()) {
            Unit unit = unitIter.next();
            Document line = sliceIter.next();
            int unitType = line.getInteger(UNIT_TYPE);

            if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value value = getLeftValue(unit, unitType);
                valueMap.put(value, unit);
            } else if ((unitType & INVOKE) == INVOKE) {
                Value localValue = getLocalValue(unit, unitType);
                String unitStr = line.getString(UNIT_STRING);

                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("java.lang.String") && methodName.equals("replace")) {
                    if (!valueMap.containsKey(localValue)) {
                        continue;
                    }

                    Unit targetUnit = valueMap.get(localValue);
                    int targetUnitType = getUnitType(targetUnit);
                    Value rightValue = getRightValue(targetUnit, targetUnitType);
                    String rightValueStr = convertToStr(rightValue);
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    String oldChar = paramValues.get(0);
                    String newChar = paramValues.get(1);

                    String newValueStr = replaceString(rightValueStr, oldChar, newChar);
                    Value newValue = StringConstant.v(newValueStr);
                    Unit newUnit = new JAssignStmt(localValue, newValue);

                    updateLine(units, slice, localValue, newUnit, rightValueStr, newValueStr);
                }
            }
        }
    }

    private String replaceString(String target, String oldChar, String newChar) {
        target = target.replace("\"", "");
        oldChar = oldChar.replace("\"", "");
        newChar = newChar.replace("\"", "");
        target = target.replace(oldChar, newChar);

        return target;
    }

    private void updateLine(ArrayList<Unit> units, ArrayList<Document> slice, Value value, Unit newUnit, String oldConstant, String newConstant) {
        Unit unit = valueMap.get(value);
        int unitIndex = units.indexOf(unit);
        if (unitIndex == -1) {
            return;
        }

        units.set(unitIndex, newUnit);
        Document line = slice.get(unitIndex);
        line.put(UNIT_STRING, newUnit.toString());

        List<String> constants = line.getList(CONSTANTS, String.class);
        if (constants == null) {
            return;
        }

        int constantIndex = constants.indexOf(oldConstant);
        constants.set(constantIndex, newConstant);
        line.put(CONSTANTS, constants);
        slice.remove(line);
    }

    private static class Holder {
        private static final SliceInterpreter instance = new SliceInterpreter();
    }
}