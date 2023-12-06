package com.ccadroid.slice;

import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.Configuration;
import org.bson.Document;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import soot.Unit;
import soot.Value;
import soot.ValueBox;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.graph.BaseGraph.EdgeType.*;
import static com.ccadroid.util.graph.CallGraph.LEVEL;
import static com.ccadroid.util.soot.Soot.isEnumClass;
import static com.ccadroid.util.soot.SootUnit.*;

public class ProgramSlicer {
    private static final int UPPER_LEVEL = Integer.parseInt(Configuration.getProperty("slice.upperLevel"));
    private static final int LOWER_LEVEL = Integer.parseInt(Configuration.getProperty("slice.lowerLevel"));
    private final CodeInspector codeInspector;
    private final SlicingCriteriaGenerator slicingCriteriaGenerator;
    private final SliceOptimizer sliceOptimizer;
    private final SliceDatabase sliceDatabase;
    private final SliceMerger sliceMerger;
    private final Deque<SlicingCriterion> deque;
    private final HashMap<String, ArrayList<Unit>> unitsMap;
    private final HashMap<Unit, HashSet<SlicingCriterion>> tempSlicingCriteriaMap;
    private HashSet<Value> newTargetVariables;

    public ProgramSlicer() {
        codeInspector = CodeInspector.getInstance();
        slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        sliceOptimizer = SliceOptimizer.getInstance();
        sliceDatabase = SliceDatabase.getInstance();
        sliceMerger = SliceMerger.getInstance();

        deque = new LinkedList<>();
        unitsMap = new HashMap<>();
        tempSlicingCriteriaMap = new HashMap<>();
    }

    public static ProgramSlicer getInstance() {
        return ProgramSlicer.Holder.instance;
    }

    public void sliceStatements(SlicingCriterion slicingCriterion) {
        String leafId = String.valueOf(slicingCriterion.hashCode());
        sliceMerger.addNode(leafId, leafId, leafId, 0);

        deque.add(slicingCriterion);

        while (!deque.isEmpty()) {
            SlicingCriterion sc = deque.poll();
            sliceStatement(sc);
        }
    }

    public ArrayList<String> getConstants(Unit unit, int unitType) {
        ArrayList<String> constants = new ArrayList<>();

        if ((unitType & INVOKE) == INVOKE) {
            String signature = getSignature(unit);
            String className = getClassName(signature);
            String methodName = getMethodName(signature);
            if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                return constants;
            }

            if (className.startsWith("android")) {
                return constants;
            }

            Value localValue = getLocalValue(unit, unitType);
            if (localValue != null && newTargetVariables.contains(localValue)) {
                return constants;
            }

            ArrayList<String> paramTypes = getParamTypes(signature);
            ArrayList<Value> paramValues = getParamValues(unit, unitType);
            int size = paramTypes.size();
            for (int i = 0; i < size; i++) {
                String paramType = paramTypes.get(i);
                if (!paramType.contains("byte") && !paramType.contains("int") && !paramType.contains("long") && !paramType.contains("float") && !paramType.contains("double") && !paramType.contains("char") && !paramType.contains("String") && !paramType.contains("Object")) {
                    continue;
                }

                Value paramValue = paramValues.get(i);
                String valueStr = convertToStr(paramValue);
                if (isVariableStr(valueStr)) {
                    continue;
                }

                if (!valueStr.equals("null")) {
                    constants.add(valueStr);
                }
            }
        } else if (unitType == ASSIGN_VARIABLE_CONSTANT || unitType == ASSIGN_SIGNATURE_CONSTANT || unitType == RETURN_VALUE) {
            Value value = getRightValue(unit, unitType);
            if (value != null) {
                String valueStr = convertToStr(value);
                if (!isVariableStr(valueStr) && !valueStr.equals("null") && !valueStr.contains("class \"")) {
                    constants.add(valueStr);
                }
            }
        }

        return constants;
    }

    public ArrayList<Unit> getUnits(String nodeId) {
        return unitsMap.get(nodeId);
    }

    private void sliceStatement(SlicingCriterion slicingCriterion) {
        String nodeId = String.valueOf(slicingCriterion.hashCode());
        String query = "{'" + NODE_ID + "': '" + nodeId + "'}";
        Document slice = sliceDatabase.findSlice(query);
        if (slice != null) {
            return;
        }

        Node node = sliceMerger.getNode(nodeId);
        String groupId = (String) node.getAttribute(GROUP_ID);

        String callerName = slicingCriterion.getCallerName();
        String targetStatement = slicingCriterion.getTargetStatement();
        int startUnitIndex = slicingCriterion.getTargetUnitIndex();
        ArrayList<Value> startTargetVariables = slicingCriterion.getTargetVariables();

        ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(callerName);
        ArrayList<Unit> reversedUnits = new ArrayList<>(wholeUnit);
        Collections.reverse(reversedUnits);

        int wholeUnitCount = wholeUnit.size();
        Unit startUnit = reversedUnits.get(startUnitIndex);
        int startUnitType = getUnitType(startUnit);
        int startLineNum = wholeUnitCount - startUnitIndex;
        String startUnitPattern = ((startUnitType & INVOKE) == INVOKE) ? getSignature(startUnit) : ((startUnitType & RETURN) == RETURN) ? "return" : startUnit.toString();
        HashMap<Integer, ArrayList<Unit>> switchTargetUnitsMap = codeInspector.getTargetUnitsMap(callerName);
        Set<Map.Entry<Integer, ArrayList<Unit>>> switchTargetUnitSet = (switchTargetUnitsMap == null) ? null : switchTargetUnitsMap.entrySet();

        newTargetVariables = new HashSet<>(startTargetVariables);
        ArrayList<String> newParamNumbers = new ArrayList<>();

        ArrayList<Unit> units = new ArrayList<>();
        units.add(startUnit);
        ArrayList<Document> content = new ArrayList<>();
        addLine(startUnit, startUnitType, callerName, startLineNum, content);

        for (int i = startUnitIndex + 1; i < wholeUnitCount; i++) {
            Unit unit = reversedUnits.get(i);
            int unitType = getUnitType(unit);
            if (unitType == -1) {
                continue;
            }

            if (unitType == CAUGHT_EXCEPTION || unitType == IF || unitType == GOTO) {
                int switchUnitIndex = (switchTargetUnitSet == null) ? -1 : getSwitchUnitIndex(unit, switchTargetUnitSet);
                if (switchUnitIndex != -1) {
                    i = switchUnitIndex;
                    continue;
                }
            }

            String unitStr = unit.toString();
            if (((unitType & INVOKE) == INVOKE && unitStr.contains(startUnitPattern)) || ((unitType & RETURN) == RETURN && unitStr.startsWith(startUnitPattern))) {
                continue;
            }

            int lineNum = wholeUnitCount - i;
            if (unitType == IF) {
                if (codeInspector.isLoopStatement(unit, unitType, reversedUnits)) {
                    continue;
                }

                Unit targetUnit = getTargetUnit(unit, unitType);
                int targetUnitIndex = reversedUnits.indexOf(targetUnit);
                if (targetUnit != null && startUnitIndex > targetUnitIndex) {
                    continue;
                }

                ArrayList<Value> conditionValues = getConditionValues(unit, unitType);
                addTargetVariables(conditionValues, newTargetVariables);

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, content);
                continue;
            } else if (unitType == GOTO) {
                if (codeInspector.isLoopStatement(unit, unitType, reversedUnits)) {
                    continue;
                }

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, content);
                continue;
            } else if (unitType == SWITCH) {
                Value value = getSwitchValue(unit, unitType);
                addTargetVariable(value, newTargetVariables);

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, content);
                continue;
            }

            List<ValueBox> useAndDefBoxes = unit.getUseAndDefBoxes();
            HashSet<Value> retainVariables = new HashSet<>();
            for (ValueBox vb : useAndDefBoxes) {
                Value value = vb.getValue();
                retainVariables.add(value);
            }
            retainVariables.retainAll(newTargetVariables);
            if (retainVariables.isEmpty()) {
                int switchUnitIndex = (switchTargetUnitSet == null) ? -1 : getSwitchUnitIndex(unit, switchTargetUnitSet);
                if (switchUnitIndex != -1) {
                    i = switchUnitIndex;
                }

                continue;
            }

            switch (unitType) {
                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case INTERFACE_INVOKE:
                case SPECIAL_INVOKE: {
                    String signature = getSignature(unitStr);
                    String className = getClassName(signature);
                    String methodName = getMethodName(signature);
                    ArrayList<Value> paramValues = getParamValues(unit, unitType);

                    if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                        Value oldValue = paramValues.get(2);
                        if (!retainVariables.contains(oldValue)) {
                            continue;
                        }

                        newTargetVariables.remove(oldValue);
                        Value newValue = paramValues.get(0);
                        addTargetVariable(newValue, newTargetVariables);
                    } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                        Value oldValue = paramValues.get(0);
                        if (!newTargetVariables.contains(oldValue)) {
                            continue;
                        }

                        Value newValue = paramValues.get(1);
                        addTargetVariable(newValue, newTargetVariables);
                    } else if (className.equals("android.util.Log") || className.equals("kotlin.jvm.internal.Intrinsics")) {
                        continue;
                    } else if (targetStatement.equals("<javax.crypto.Mac: void doFinal(byte[],int)>") &&
                            className.equals("javax.crypto.Mac") && methodName.equals("update")) {
                        Value newValue = paramValues.get(0);
                        addTargetVariable(newValue, newTargetVariables);
                    } else {
                        Value localValue = getLocalValue(unit, unitType);
                        if (localValue != null) {
                            addTargetVariable(localValue, newTargetVariables);
                        }

                        handleInvokeUnit(unit, node, groupId, signature);
                    }

                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_INTERFACE_INVOKE:
                case ASSIGN_SPECIAL_INVOKE: {
                    String signature = getSignature(unitStr);
                    String methodName = getMethodName(signature);
                    if (methodName.contains("$")) { // for virtual method
                        Value leftValue = getLeftValue(unit, unitType);
                        newTargetVariables.remove(leftValue);
                    }

                    Value localValue = getLocalValue(unit, unitType);
                    if (localValue == null) {
                        ArrayList<String> paramTypes = getParamTypes(signature);
                        ArrayList<Value> paramValues = getParamValues(unit, unitType);

                        addTargetVariables(paramTypes, paramValues, newTargetVariables);
                    } else {
                        addTargetVariable(localValue, newTargetVariables);
                    }

                    handleInvokeUnit(unit, node, groupId, signature);
                    break;
                }

                case PARAMETER: {
                    String paramNumber = getParamNumber(unitStr, unitType);
                    newParamNumbers.add(0, paramNumber);
                    break;
                }

                case NEW_INSTANCE:
                case NEW_ARRAY:
                case ASSIGN_VARIABLE_CONSTANT: {
                    Value value = getLeftValue(unit, unitType);
                    if (!retainVariables.contains(value)) {
                        continue;
                    }

                    break;
                }

                case ASSIGN_VARIABLE_VARIABLE:
                case CAST:
                case LENGTH_OF: {
                    Value leftValue = getLeftValue(unit, unitType);
                    if (!retainVariables.contains(leftValue)) {
                        continue;
                    }

                    newTargetVariables.remove(leftValue);
                    Value rightValue = (unitType == ASSIGN_VARIABLE_VARIABLE) ? getRightValue(unit, unitType) : getRightInternalValue(unit, unitType);
                    newTargetVariables.add(rightValue);
                    break;
                }

                case ASSIGN_VARIABLE_SIGNATURE: {
                    if (startUnitType == ASSIGN_SIGNATURE_VARIABLE) {
                        Value leftValue = getLeftValue(unit, unitType);
                        newTargetVariables.remove(leftValue);

                        Value rightValue = getRightValue(unit, unitType);
                        newTargetVariables.add(rightValue);
                    }

                    String signature = getSignature(unitStr);
                    handleAssignVariableSignatureUnit(unit, node, groupId, callerName, signature);
                    break;
                }

                case ASSIGN_VARIABLE_ADD: {
                    Unit prevUnit = reversedUnits.get(i - 1);
                    int prevUnitType = getUnitType(prevUnit);
                    if (prevUnitType == GOTO) {
                        Value value = getLeftValue(unit, unitType);
                        newTargetVariables.remove(value);
                        continue;
                    }

                    break;
                }

                case RETURN_VALUE: {
                    Value value = getRightValue(unit, unitType);
                    if (retainVariables.contains(value)) {
                        continue; // ignore return statement
                    } else {
                        break;
                    }
                }

                default: {
                    break;
                }
            }

            units.add(0, unit);
            addLine(unit, unitType, callerName, lineNum, content);
        }

        ArrayList<Unit> unreachables = sliceOptimizer.getUnreachableUnits(wholeUnit, units);
        units.removeAll(unreachables);

        HashMap<Unit, Unit> updates = sliceOptimizer.getInterpretedUnits(units, new HashMap<>());
        sliceOptimizer.updateLines(updates, content);
        unitsMap.put(nodeId, units);

        ArrayList<String> targetParamNumbers = slicingCriterion.getTargetParamNumbers();
        if (targetParamNumbers == null || !targetParamNumbers.isEmpty()) {
            handleParameterUnit(node, groupId, callerName, newParamNumbers);
        }

        addTempSlicingCriteria(units);
        removeTempSlicingCriteria(unreachables);

        sliceDatabase.insert(nodeId, groupId, callerName, targetStatement, startUnitIndex, targetParamNumbers, convertToStrings(startTargetVariables), content);
    }

    private int getSwitchUnitIndex(Unit unit, Set<Map.Entry<Integer, ArrayList<Unit>>> switchTargetUnitSet) {
        int index = -1;

        for (Map.Entry<Integer, ArrayList<Unit>> e : switchTargetUnitSet) {
            ArrayList<Unit> targetUnits = e.getValue();
            if (!targetUnits.contains(unit)) {
                continue;
            }

            index = e.getKey() - 1;
            break;
        }

        return index;
    }

    private void addTargetVariable(Value value, HashSet<Value> newTargetVariables) {
        String valueStr = convertToStr(value);
        if (!isVariableStr(valueStr)) {
            return;
        }

        newTargetVariables.add(value);
    }

    private void addTargetVariables(ArrayList<String> paramTypes, ArrayList<Value> values, HashSet<Value> newTargetVariables) {
        int size = paramTypes.size();
        for (int i = 0; i < size; i++) {
            String paramType = paramTypes.get(i);
            if (!paramType.contains("byte") && !paramType.contains("char") && !paramType.contains("String") && !paramType.contains("Object")) {
                continue;
            }

            Value value = values.get(i);
            if (paramType.contains("Object")) {
                newTargetVariables.add(value);
            } else {
                addTargetVariable(value, newTargetVariables);
            }
        }
    }

    private void addTargetVariables(ArrayList<Value> values, HashSet<Value> newTargetVariables) {
        for (Value v : values) {
            addTargetVariable(v, newTargetVariables);
        }
    }

    private void handleInvokeUnit(Unit unit, Node parent, String groupId, String calleeName) {
        int level = (int) parent.getAttribute(LEVEL);
        if (level == LOWER_LEVEL) {
            return;
        } else {
            level--;
        }

        ArrayList<SlicingCriterion> slicingCriteria;
        ArrayList<String> paramNumbers = new ArrayList<>();

        int unitType = getUnitType(unit);
        if ((unitType & ASSIGN) == ASSIGN) { // for ASSIGN_INVOKE_UNIT
            slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "return", RETURN_VALUE, paramNumbers);
        } else {
            slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "", INVOKE, paramNumbers);
        }

        for (SlicingCriterion sc : slicingCriteria) {
            String childId = String.valueOf(sc.hashCode());
            Node child = sliceMerger.addNode(childId, childId, groupId, level);
            sliceMerger.addEdge(parent, child, DOWNWARD);
        }

        HashSet<SlicingCriterion> tempSlicingCriteria = new HashSet<>(slicingCriteria);
        tempSlicingCriteriaMap.put(unit, tempSlicingCriteria);
    }

    private void handleAssignVariableSignatureUnit(Unit unit, Node sibling, String groupId, String oldCallerName, String targetSignature) {
        Node oldCaller = codeInspector.getNode(oldCallerName);
        int level = (int) sibling.getAttribute(LEVEL);
        String newSiblingId = String.valueOf(targetSignature.hashCode());
        Node newSibling = sliceMerger.getNode(newSiblingId);
        if (newSibling == null) {
            newSibling = sliceMerger.addNode(newSiblingId, newSiblingId, groupId, level);
            sliceMerger.addEdge(sibling, newSibling, NONE);
        }

        level++;

        Node valueNode = codeInspector.getNode(targetSignature);
        if (valueNode == null) {
            return;
        }

        HashSet<SlicingCriterion> tempSlicingCriteria = new HashSet<>();
        Stream<Edge> stream = valueNode.edges();
        List<Edge> edges = stream.collect(Collectors.toList());
        for (Edge e : edges) {
            Node newCaller = e.getSourceNode();
            if (newCaller.equals(oldCaller)) {
                continue;
            }

            String newCallerName = newCaller.getId();
            String className = getClassName(newCallerName);
            if (isEnumClass(className)) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(newCallerName, targetSignature, ASSIGN, null);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId = String.valueOf(sc.hashCode());
                Node parent = sliceMerger.addNode(parentId, parentId, groupId, level);
                sliceMerger.addEdge(newSibling, parent, UPWARD);
            }

            tempSlicingCriteria.addAll(slicingCriteria);
        }

        tempSlicingCriteriaMap.put(unit, tempSlicingCriteria);
    }

    private void handleParameterUnit(Node child, String groupId, String calleeName, ArrayList<String> paramNumbers) {
        if (paramNumbers.isEmpty()) {
            return;
        }

        int level = (int) child.getAttribute(LEVEL);
        if (level == UPPER_LEVEL) {
            return;
        } else {
            level++;
        }

        Node callee = codeInspector.getNode(calleeName);
        Stream<Edge> stream = callee.enteringEdges();
        List<Edge> edges = stream.collect(Collectors.toList());
        for (Edge e : edges) {
            Node caller = e.getSourceNode();
            String callerName = caller.getId();

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(callerName, calleeName, INVOKE, paramNumbers);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId = String.valueOf(sc.hashCode());
                Node parent = sliceMerger.addNode(parentId, parentId, groupId, level);
                sliceMerger.addEdge(child, parent, UPWARD);
                deque.add(sc);
            }
        }
    }

    private void addLine(Unit unit, int unitType, String callerName, int lineNum, ArrayList<Document> slice) {
        String unitStr = unit.toString();

        Document line = new Document();
        line.append(UNIT_STRING, unitStr);
        line.append(UNIT_TYPE, unitType);
        line.append(CALLER_NAME, callerName);
        line.append(LINE_NUM, lineNum);
        if ((unitType & INVOKE) == INVOKE || unitType == ASSIGN_VARIABLE_CONSTANT || unitType == ASSIGN_SIGNATURE_CONSTANT || unitType == RETURN_VALUE) {
            ArrayList<String> constants = getConstants(unit, unitType);
            if (!constants.isEmpty()) {
                line.append(CONSTANTS, constants);
            }
        } else if (unitType == NEW_ARRAY) {
            String size = getArraySize(unit, unitType);
            line.append(ARRAY_SIZE, size);
        }

        slice.add(0, line);
    }

    private void removeTempSlicingCriteria(ArrayList<Unit> unreachableUnits) {
        for (Unit u : unreachableUnits) {
            HashSet<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.remove(u);
            if (tempSlicingCriteria == null) {
                continue;
            }

            deque.removeAll(tempSlicingCriteria);
        }
    }

    private void addTempSlicingCriteria(ArrayList<Unit> units) {
        for (Unit u : units) {
            HashSet<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.remove(u);
            if (tempSlicingCriteria == null) {
                continue;
            }

            deque.addAll(tempSlicingCriteria);
        }
    }

    private static class Holder {
        private static final ProgramSlicer instance = new ProgramSlicer();
    }
}