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

                    String newStr = replaceString(rightValueStr, paramValues.get(0), paramValues.get(1));
                    Value newValue = StringConstant.v(newStr);
                    Unit newUnit = new JAssignStmt(localValue, newValue);

                    updateSlice(units, slice, localValue, newUnit, rightValueStr, newStr);
                    slice.remove(line);
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

    private void updateSlice(ArrayList<Unit> units, ArrayList<Document> slice, Value value, Unit newUnit, String oldConstant, String newConstant) {
        Unit oldUnit = valueMap.get(value);
        int index = units.indexOf(oldUnit);
        units.set(index, newUnit);

        Document oldLine = slice.get(index);
        oldLine.put(UNIT_STRING, newUnit.toString());

        List<String> constants = oldLine.getList(CONSTANTS, String.class);
        if (constants == null) {
            return;
        }

        constants.set(constants.indexOf(oldConstant), newConstant);
        oldLine.put(CONSTANTS, constants);
    }

    private static class Holder {
        private static final SliceInterpreter instance = new SliceInterpreter();
    }
}