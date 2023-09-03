package com.ccadroid.util.soot;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import soot.Unit;
import soot.UnitBox;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;
import soot.jimple.internal.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SootUnit {
    public static final int INVOKE = 0x00100000;
    public static final int VIRTUAL_INVOKE = INVOKE | 0x00001000;
    public static final int STATIC_INVOKE = INVOKE | 0x00002000;
    public static final int INTERFACE_INVOKE = INVOKE | 0x00004000;
    public static final int SPECIAL_INVOKE = INVOKE | 0x00008000;
    public static final int ASSIGN = 0x00200000;
    public static final int ASSIGN_INVOKE = ASSIGN | INVOKE;
    public static final int ASSIGN_VIRTUAL_INVOKE = ASSIGN_INVOKE | VIRTUAL_INVOKE;
    public static final int ASSIGN_STATIC_INVOKE = ASSIGN_INVOKE | STATIC_INVOKE;
    public static final int ASSIGN_INTERFACE_INVOKE = ASSIGN_INVOKE | INTERFACE_INVOKE;
    public static final int ASSIGN_SPECIAL_INVOKE = ASSIGN_INVOKE | SPECIAL_INVOKE;
    public static final int IDENTITY = ASSIGN | 0x00000010;
    public static final int PARAMETER = IDENTITY | 0x00000001;
    public static final int CAUGHT_EXCEPTION = IDENTITY | 0x00000002;
    public static final int NEW_INSTANCE = ASSIGN | 0x00000020;
    public static final int NEW_ARRAY = ASSIGN | 0x00000040;
    public static final int NEW_EXCEPTION = ASSIGN | 0x00000080;
    public static final int ASSIGN_VARIABLE_CONSTANT = ASSIGN | 0x00000100;
    public static final int ASSIGN_VARIABLE_VARIABLE = ASSIGN | 0x00000101;
    public static final int ASSIGN_VARIABLE_ARRAY = ASSIGN | 0x00000102;
    public static final int ASSIGN_VARIABLE_SIGNATURE = ASSIGN | 0x00000104;
    public static final int ASSIGN_VARIABLE_ADD = ASSIGN | 0x00000108;
    public static final int ASSIGN_ARRAY_CONSTANT = ASSIGN | 0x00000200;
    public static final int ASSIGN_ARRAY_VARIABLE = ASSIGN | 0x00000201;
    public static final int ASSIGN_SIGNATURE_CONSTANT = ASSIGN | 0x00000400;
    public static final int ASSIGN_SIGNATURE_VARIABLE = ASSIGN | 0x00000401;
    public static final int CAST = ASSIGN | 0x00010000;
    public static final int LENGTH_OF = ASSIGN | 0x00020000;
    public static final int INSTANCE_OF = ASSIGN | 0x00040000;
    public static final int IF = 0x00400000;
    public static final int GOTO = 0x008000000;
    public static final int SWITCH = 0x01000000;
    public static final int RETURN = 0x02000000;
    public static final int RETURN_VALUE = RETURN | 0x00000001;
    public static final int RETURN_VOID = RETURN | 0x00000002;
    private static final Pattern NUMBER_PATTERN = Pattern.compile("\\d+");
    private static final Pattern VARIABLE_PATTERN = Pattern.compile("\\$*[a-z]\\d{1,5}");

    private SootUnit() throws InstantiationException {
        throw new InstantiationException();
    }

    public static int getUnitType(Unit unit) {
        int type = -1;

        if (isVirtualInvoke(unit)) {
            type = VIRTUAL_INVOKE;
        } else if (isStaticInvoke(unit)) {
            type = STATIC_INVOKE;
        } else if (isInterfaceInvoke(unit)) {
            type = INTERFACE_INVOKE;
        } else if (isSpecialInvoke(unit)) {
            type = SPECIAL_INVOKE;
        } else if (isAssignVirtualInvoke(unit)) {
            type = ASSIGN_VIRTUAL_INVOKE;
        } else if (isAssignStaticInvoke(unit)) {
            type = ASSIGN_STATIC_INVOKE;
        } else if (isAssignInterfaceInvoke(unit)) {
            type = ASSIGN_INTERFACE_INVOKE;
        } else if (isAssignSpecialInvoke(unit)) {
            type = ASSIGN_SPECIAL_INVOKE;
        } else if (isParameter(unit)) {
            type = PARAMETER;
        } else if (isCaughtException(unit)) {
            type = CAUGHT_EXCEPTION;
        } else if (isNewInstance(unit)) {
            type = NEW_INSTANCE;
        } else if (isNewArray(unit)) {
            type = NEW_ARRAY;
        } else if (isNewException(unit)) {
            type = NEW_EXCEPTION;
        } else if (isAssignVariableConstant(unit)) {
            type = ASSIGN_VARIABLE_CONSTANT;
        } else if (isAssignVariableVariable(unit)) {
            type = ASSIGN_VARIABLE_VARIABLE;
        } else if (isAssignVariableArray(unit)) {
            type = ASSIGN_VARIABLE_ARRAY;
        } else if (isAssignVariableSignature(unit)) {
            type = ASSIGN_VARIABLE_SIGNATURE;
        } else if (isAssignVariableAdd(unit)) {
            type = ASSIGN_VARIABLE_ADD;
        } else if (isAssignSignatureConstant(unit)) {
            type = ASSIGN_SIGNATURE_CONSTANT;
        } else if (isAssignSignatureVariable(unit)) {
            type = ASSIGN_SIGNATURE_VARIABLE;
        } else if (isAssignArrayConstant(unit)) {
            type = ASSIGN_ARRAY_CONSTANT;
        } else if (isAssignArrayVariable(unit)) {
            type = ASSIGN_ARRAY_VARIABLE;
        } else if (isCast(unit)) {
            type = CAST;
        } else if (isLengthOf(unit)) {
            type = LENGTH_OF;
        } else if (isInstanceOf(unit)) {
            type = INSTANCE_OF;
        } else if (isIf(unit)) {
            type = IF;
        } else if (isGoto(unit)) {
            type = GOTO;
        } else if (isSwitch(unit)) {
            type = SWITCH;
        } else if (isReturnValue(unit)) {
            type = RETURN_VALUE;
        } else if (isReturnVoid(unit)) {
            type = RETURN_VOID;
        } else if (isAssign(unit)) {
            type = ASSIGN; // other assign unit
        }

        return type;
    }

    public static String getSignature(Unit unit) {
        String unitStr = unit.toString();

        return getSignature(unitStr);
    }

    public static String getSignature(String unitStr) {
        StringTokenizer tokenizer = new StringTokenizer(unitStr, ">");
        String str = tokenizer.nextToken();

        StringBuilder buffer = new StringBuilder();
        buffer.append(str.substring(str.indexOf("<")));
        if (unitStr.contains("<init>")) {
            buffer.append(">");
            buffer.append(tokenizer.nextToken());
        }

        buffer.append(">");

        return buffer.toString();
    }

    public static String getClassName(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        String str = tokenizer.nextToken();

        return str.substring(1, str.length() - 1);
    }

    public static String getReturnType(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();

        return tokenizer.nextToken();
    }

    public static String getMethodName(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();
        tokenizer.nextToken();
        String str = tokenizer.nextToken();

        return str.substring(0, str.indexOf('('));
    }

    public static ArrayList<String> getParamTypes(String signature) {
        String str = signature.substring(signature.indexOf("(") + 1, signature.length() - 2);

        return convertToList(str);
    }

    public static ValueBox getLocalValueBox(Unit unit, int unitType) {
        if ((unitType & VIRTUAL_INVOKE) != VIRTUAL_INVOKE) {
            return null;
        }

        ValueBox valueBox;
        if ((unitType & ASSIGN) == ASSIGN) {
            Value value = getRightValue(unit, unitType);
            if (value == null) {
                return null;
            }

            InstanceInvokeExpr expr = (InstanceInvokeExpr) value;
            valueBox = expr.getBaseBox();
        } else {
            InvokeStmt stmt = (InvokeStmt) unit;
            InstanceInvokeExpr expr = (InstanceInvokeExpr) stmt.getInvokeExpr();
            valueBox = expr.getBaseBox();
        }

        return valueBox;
    }

    public static ArrayList<ValueBox> getParamValues(Unit unit, int unitType) {
        if ((unitType & INVOKE) != INVOKE) {
            return new ArrayList<>();
        }

        InvokeExpr expr;
        if ((unitType & ASSIGN) == ASSIGN) {
            Value value = getRightValue(unit, unitType);
            expr = (value == null) ? null : (InvokeExpr) value;
        } else {
            JInvokeStmt stmt = (JInvokeStmt) unit;
            expr = stmt.getInvokeExpr();
        }

        if (expr == null) {
            return new ArrayList<>();
        }

        ArrayList<ValueBox> paramValues = new ArrayList<>();
        for (int i = 0; i < expr.getArgCount(); i++) {
            ValueBox argBox = expr.getArgBox(i);
            paramValues.add(argBox);
        }

        return paramValues;
    }

    public static ArrayList<String> getParamValues(String unitStr) {
        String str = unitStr.substring(unitStr.indexOf(")>") + 3, unitStr.length() - 1);
        return convertToList(str);
    }

    public static ArrayList<String> convertToStrings(List<ValueBox> valueBoxes) {
        ArrayList<String> strings = new ArrayList<>();

        for (ValueBox vb : valueBoxes) {
            String valueStr = getValueStr(vb);
            strings.add(valueStr);
        }

        return strings;
    }

    public static ValueBox getLeftValueBox(Unit unit, int unitType) {
        if ((unitType & ASSIGN) != ASSIGN) {
            return null;
        }

        ValueBox valueBox;
        if ((unitType & IDENTITY) == IDENTITY) {
            IdentityStmt stmt = (JIdentityStmt) unit;
            valueBox = stmt.getLeftOpBox();
        } else {
            JAssignStmt stmt = (JAssignStmt) unit;
            valueBox = stmt.getLeftOpBox();
        }

        return valueBox;
    }

    public static Value getLeftValue(Unit unit, int unitType) {
        ValueBox valueBox = getLeftValueBox(unit, unitType);

        return (valueBox == null) ? null : valueBox.getValue();
    }

    public static ValueBox getRightValueBox(Unit unit, int unitType) {
        if ((unitType & ASSIGN) != ASSIGN) {
            return null;
        }

        ValueBox valueBox;
        if ((unitType & IDENTITY) == IDENTITY) {
            JIdentityStmt stmt = (JIdentityStmt) unit;
            valueBox = stmt.getRightOpBox();
        } else if (unitType == RETURN_VALUE) {
            JReturnStmt stmt = (JReturnStmt) unit;
            valueBox = stmt.getOpBox();
        } else {
            JAssignStmt stmt = (JAssignStmt) unit;
            valueBox = stmt.getRightOpBox();
        }

        return valueBox;
    }

    public static Value getRightValue(Unit unit, int unitType) {
        ValueBox valueBox = getRightValueBox(unit, unitType);

        return (valueBox == null) ? null : valueBox.getValue();
    }

    public static ValueBox getRightInternalValue(Unit unit, int unitType) {
        if (unitType != CAST && unitType != LENGTH_OF) {
            return null;
        }

        Value value = getRightValue(unit, unitType);
        if (value == null) {
            return null;
        }

        ValueBox valueBox;
        if (unitType == CAST) {
            JCastExpr expr = (JCastExpr) value;
            valueBox = expr.getOpBox();
        } else {
            JLengthExpr expr = (JLengthExpr) value;
            valueBox = expr.getOpBox();
        }

        return valueBox;
    }

    public static String getValueStr(ValueBox valueBox) {
        Value value = (valueBox == null) ? null : valueBox.getValue();

        return convertToStr(value);
    }

    public static String convertToStr(Value value) {
        return (value == null) ? "null" : value.toString();
    }

    public static boolean isVariableStr(String s) {
        if (s == null) {
            return false;
        }

        Matcher matcher = VARIABLE_PATTERN.matcher(s);

        return matcher.matches();
    }

    public static String getParamNum(Unit unit, int unitType) {
        String unitStr = unit.toString();

        return getParamNum(unitStr, unitType);
    }

    public static String getParamNum(String unitStr, int unitType) {
        if (unitType != PARAMETER) {
            return null;
        }

        Matcher matcher = NUMBER_PATTERN.matcher(unitStr);
        matcher.find();

        return matcher.group();
    }

    public static Value getConditionValue(Unit unit, int unitType) {
        if (unitType != IF) {
            return null;
        }

        JIfStmt stmt = (JIfStmt) unit;
        ValueBox conditionBox = stmt.getConditionBox();

        return conditionBox.getValue();
    }

    public static ArrayList<ValueBox> getConditionValues(Unit unit, int unitType) {
        Value value = getConditionValue(unit, unitType);

        return (value == null) ? new ArrayList<>() : new ArrayList<>(value.getUseBoxes());
    }

    public static Unit getTargetUnit(Unit unit, int unitType) {
        if ((unitType != IF) && (unitType != GOTO)) {
            return null;
        }

        Unit targetUnit;
        if (unitType == IF) {
            JIfStmt stmt = (JIfStmt) unit;
            UnitBox unitBox = stmt.getTargetBox();
            targetUnit = unitBox.getUnit();
        } else {
            JGotoStmt stmt = (JGotoStmt) unit;
            targetUnit = stmt.getTarget();
        }

        return targetUnit;
    }

    public static ValueBox getSwitchValueBox(Unit unit, int unitType) {
        if (unitType != SWITCH) {
            return null;
        }

        SwitchStmt stmt = (JLookupSwitchStmt) unit;

        return stmt.getKeyBox();
    }

    public static ArrayList<Unit> getTargetUnits(Unit unit, int unitType) {
        if (unitType != SWITCH) {
            return new ArrayList<>();
        }

        SwitchStmt stmt = (JLookupSwitchStmt) unit;
        List<Unit> targets = stmt.getTargets();
        ArrayList<Unit> targetUnits = new ArrayList<>(targets);
        Unit defaultUnit = stmt.getDefaultTarget();
        targetUnits.add(defaultUnit);

        return targetUnits;
    }

    private static boolean isInvoke(Unit unit) {
        return unit instanceof JInvokeStmt;
    }

    private static boolean isVirtualInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JVirtualInvokeExpr;
    }

    private static boolean isStaticInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JStaticInvokeExpr;
    }

    private static boolean isInterfaceInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JInterfaceInvokeExpr;
    }

    private static boolean isSpecialInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JSpecialInvokeExpr;
    }

    private static boolean isAssign(Unit unit) {
        return unit instanceof JAssignStmt;
    }

    private static boolean isAssignVirtualInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JVirtualInvokeExpr;
    }

    private static boolean isAssignStaticInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JStaticInvokeExpr;
    }

    private static boolean isAssignInterfaceInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JInterfaceInvokeExpr;
    }

    private static boolean isAssignSpecialInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JSpecialInvokeExpr;
    }

    private static boolean isIdentity(Unit unit) {
        return unit instanceof IdentityStmt;
    }

    private static boolean isParameter(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        Value value = getRightValue(unit, PARAMETER);

        return value instanceof ParameterRef;
    }

    private static boolean isCaughtException(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        Value value = getRightValue(unit, CAUGHT_EXCEPTION);

        return value instanceof CaughtExceptionRef;
    }

    private static boolean isNewInstance(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);
        String valueStr = convertToStr(value);

        return (value instanceof JNewExpr) && (!valueStr.endsWith("Exception"));
    }

    private static boolean isNewArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JNewArrayExpr;
    }

    private static boolean isNewException(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);
        String valueStr = convertToStr(value);

        return (value instanceof JNewExpr) && (valueStr.endsWith("Exception"));
    }

    private static boolean isAssignVariableConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof Constant);
    }

    private static boolean isAssignVariableVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isAssignVariableArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JArrayRef);
    }

    private static boolean isAssignVariableSignature(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof StaticFieldRef || rightValue instanceof JInstanceFieldRef);
    }

    private static boolean isAssignVariableAdd(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JAddExpr);
    }

    private static boolean isAssignSignatureConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof StaticFieldRef || leftValue instanceof JInstanceFieldRef) && (rightValue instanceof Constant);
    }

    private static boolean isAssignSignatureVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof StaticFieldRef || leftValue instanceof JInstanceFieldRef) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isAssignArrayConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JArrayRef) && (rightValue instanceof Constant);
    }

    private static boolean isAssignArrayVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JArrayRef) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isCast(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, CAST);

        return value instanceof JCastExpr;
    }

    private static boolean isLengthOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, LENGTH_OF);

        return value instanceof JLengthExpr;
    }

    private static boolean isInstanceOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, INSTANCE_OF);

        return value instanceof JInstanceOfExpr;
    }

    private static boolean isIf(Unit unit) {
        return unit instanceof JIfStmt;
    }

    private static boolean isGoto(Unit unit) {
        return unit instanceof JGotoStmt;
    }

    private static boolean isSwitch(Unit unit) {
        return unit instanceof JLookupSwitchStmt;
    }

    private static boolean isReturnValue(Unit unit) {
        return unit instanceof JReturnStmt;
    }

    private static boolean isReturnVoid(Unit unit) {
        return unit instanceof JReturnVoidStmt;
    }

    private static ArrayList<String> convertToList(String s) {
        ArrayList<String> list = new ArrayList<>();

        try {
            StringReader stringReader = new StringReader(s);
            CSVReader csvReader = new CSVReader(stringReader);
            String[] tokens = csvReader.readNext();
            for (String t : tokens) {
                t = t.trim();
                list.add(t);
            }
        } catch (IOException | CsvValidationException | NullPointerException ignored) {

        }

        return list;
    }
}