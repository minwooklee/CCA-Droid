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
    private final SliceInterpreter sliceInterpreter;
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
        sliceInterpreter = SliceInterpreter.getInstance();
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

    public ArrayList<Unit> getUnits(String nodeId) {
        return unitsMap.get(nodeId);
    }

    private void sliceStatement(SlicingCriterion slicingCriterion) {
        String nodeId = String.valueOf(slicingCriterion.hashCode());
        if (sliceDatabase.selectCount("{'" + NODE_ID + "': '" + nodeId + "'}") > 0) {
            return;
        }

        Node node = sliceMerger.getNode(nodeId);
        String groupId = (String) node.getAttribute(GROUP_ID);

        String callerName = slicingCriterion.getCallerName();
        String targetSignature = slicingCriterion.getTargetSignature();
        int startUnitIndex = slicingCriterion.getTargetUnitIndex();
        HashSet<Value> oldTargetVariables = slicingCriterion.getTargetVariables();
        ArrayList<String> targetVariables = new ArrayList<>();
        for (Value v : oldTargetVariables) {
            String valueStr = convertToStr(v);
            targetVariables.add(valueStr);
        }

        ArrayList<Unit> tempWholeUnits = codeInspector.getWholeUnits(callerName);
        ArrayList<Unit> wholeUnits = new ArrayList<>(tempWholeUnits);
        Collections.reverse(wholeUnits);

        int wholeUnitCount = wholeUnits.size();
        Unit startUnit = wholeUnits.get(startUnitIndex);
        int startUnitType = getUnitType(startUnit);
        int startLineNum = wholeUnitCount - startUnitIndex;
        HashMap<Integer, ArrayList<Unit>> switchTargetUnitMap = codeInspector.getTargetUnits(callerName);
        Set<Map.Entry<Integer, ArrayList<Unit>>> switchTargetUnitSet = (switchTargetUnitMap == null) ? null : switchTargetUnitMap.entrySet();

        newTargetVariables = new HashSet<>(oldTargetVariables);
        ArrayList<String> newParamNums = new ArrayList<>();

        ArrayList<Unit> units = new ArrayList<>();
        units.add(startUnit);
        ArrayList<Document> slice = new ArrayList<>();
        addLine(startUnit, startUnitType, callerName, startLineNum, slice);

        for (int i = startUnitIndex + 1; i < wholeUnitCount; i++) {
            Unit unit = wholeUnits.get(i);
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
            int lineNum = wholeUnitCount - i;
            if (unitType == IF) {
                if (codeInspector.isLoopStatement(unit, unitType, wholeUnits)) {
                    continue;
                }

                Unit targetUnit = getTargetUnit(unit, unitType);
                int targetUnitIndex = wholeUnits.indexOf(targetUnit);
                if (targetUnit != null && startUnitIndex > targetUnitIndex) {
                    continue;
                }

                ArrayList<Value> conditionValues = getConditionValues(unit, unitType);
                addTargetVariables(conditionValues, newTargetVariables);

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, slice);
                continue;
            } else if (unitType == GOTO) {
                if (codeInspector.isLoopStatement(unit, unitType, wholeUnits)) {
                    continue;
                }

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, slice);
                continue;
            } else if (unitType == SWITCH) {
                Value value = getSwitchValue(unit, unitType);
                addTargetVariable(value, newTargetVariables);

                units.add(0, unit);
                addLine(unit, unitType, callerName, lineNum, slice);
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
                    } else {
                        Value localValue = getLocalValue(unit, unitType);
                        if (localValue != null) {
                            addTargetVariable(localValue, newTargetVariables);
                        }

                        ArrayList<String> paramTypes = getParamTypes(signature);
                        addTargetVariables(paramTypes, paramValues, newTargetVariables);
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

                    handleAssignInvokeUnit(unit, node, groupId, signature);
                    break;
                }

                case PARAMETER: {
                    String paramNum = getParamNum(unitStr, unitType);
                    newParamNums.add(0, paramNum);
                    break;
                }

                case NEW_INSTANCE:
                case NEW_ARRAY:
                case ASSIGN_VARIABLE_CONSTANT: {
                    Value Value = getLeftValue(unit, unitType);
                    if (!retainVariables.contains(Value)) {
                        continue;
                    }

                    break;
                }

                case ASSIGN_VARIABLE_VARIABLE: {
                    Value leftValue = getLeftValue(unit, unitType);
                    if (!retainVariables.contains(leftValue)) {
                        continue;
                    }

                    newTargetVariables.remove(leftValue);
                    Value rightValue = getRightValue(unit, unitType);
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
                    Unit targetUnit = wholeUnits.get(i - 1);
                    int targetUnitType = getUnitType(targetUnit);
                    if (targetUnitType == GOTO) {
                        Value value = getLeftValue(unit, unitType);
                        newTargetVariables.remove(value);
                        continue;
                    }

                    break;
                }

                case CAST:
                case LENGTH_OF: {
                    Value leftValue = getLeftValue(unit, unitType);
                    if (!retainVariables.contains(leftValue)) {
                        continue;
                    }

                    newTargetVariables.remove(leftValue);
                    Value rightValue = getRightInternalValue(unit, unitType);
                    newTargetVariables.add(rightValue);
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
            addLine(unit, unitType, callerName, lineNum, slice);
        }

        ArrayList<Unit> unreachableUnits = sliceOptimizer.getUnreachableUnits(tempWholeUnits, units);
        removeTempSlicingCriteria(unreachableUnits);

        units.removeAll(unreachableUnits);
        sliceInterpreter.interpret(units, slice);
        unitsMap.put(nodeId, units);

        handleParameterUnit(node, groupId, callerName, newParamNums);

        addTempSlicingCriteria(units);
        sliceDatabase.insert(nodeId, groupId, callerName, targetSignature, startUnitIndex, targetVariables, slice);
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
            if (!paramType.contains("char") && !paramType.contains("String") && !paramType.contains("byte")) {
                continue;
            }

            Value value = values.get(i);
            addTargetVariable(value, newTargetVariables);
        }
    }

    private void addTargetVariables(ArrayList<Value> values, HashSet<Value> newTargetVariables) {
        for (Value v : values) {
            addTargetVariable(v, newTargetVariables);
        }
    }

    private void handleAssignInvokeUnit(Unit unit, Node parent, String groupId, String calleeName) {
        int level = (int) parent.getAttribute(LEVEL);
        if (level == LOWER_LEVEL) {
            return;
        } else {
            level--;
        }

        ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "return", RETURN_VALUE, null);
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

    private void handleParameterUnit(Node child, String groupId, String calleeName, ArrayList<String> paramNums) {
        if (paramNums.isEmpty()) {
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

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(callerName, calleeName, INVOKE, paramNums);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId = String.valueOf(sc.hashCode());
                Node parent = sliceMerger.addNode(parentId, parentId, groupId, level);
                sliceMerger.addEdge(child, parent, UPWARD);
                deque.add(sc);
            }
        }
    }

    private void addLine(Unit unit, int unitType, String callerName, int lineNum, ArrayList<Document> slice) {
        Document line = new Document();
        line.append(UNIT_STRING, unit.toString());
        line.append(UNIT_TYPE, unitType);
        line.append(CALLER_NAME, callerName);
        line.append(LINE_NUMBER, lineNum);
        if ((unitType & INVOKE) == INVOKE || unitType == ASSIGN_VARIABLE_CONSTANT || unitType == ASSIGN_SIGNATURE_CONSTANT) {
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

    private ArrayList<String> getConstants(Unit unit, int unitType) {
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
                if (!paramType.contains("int") && !paramType.contains("char") && !paramType.contains("String") && !paramType.contains("byte")) {
                    continue;
                }

                Value paramValue = paramValues.get(i);
                String valueStr = convertToStr(paramValue);
                if (isVariableStr(valueStr)) {
                    continue;
                }

                valueStr = valueStr.replace("\"", "");
                constants.add(valueStr);
            }
        } else if (unitType == ASSIGN_VARIABLE_CONSTANT || unitType == ASSIGN_SIGNATURE_CONSTANT) {
            Value value = getRightValue(unit, unitType);
            if (value != null) {
                String valueStr = convertToStr(value);
                valueStr = valueStr.replace("\"", "");

                if (!valueStr.equals("") && !valueStr.equals("null")) {
                    constants.add(valueStr);
                }
            }
        }

        return constants;
    }

    private void removeTempSlicingCriteria(ArrayList<Unit> unreachableUnits) {
        for (Unit u : unreachableUnits) {
            HashSet<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.remove(u);
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