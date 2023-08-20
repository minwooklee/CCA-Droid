package com.ccadroid.slice;

import com.ccadroid.common.model.SlicingCriterion;
import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import org.bson.Document;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import soot.Unit;
import soot.Value;
import soot.ValueBox;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ccadroid.util.graph.BaseGraph.EdgeType.*;
import static com.ccadroid.util.soot.Soot.isEnumClass;
import static com.ccadroid.util.soot.SootUnit.*;

public class ProgramSlicer {
    private static final int UPPER_LEVEL = 5;
    private static final int LOWER_LEVEL = -5;
    private final CodeInspector codeInspector;
    private final SlicingCriteriaGenerator slicingCriteriaGenerator;
    private final SliceDatabase sliceDatabase;
    private final SliceMerger sliceMerger;
    private final Deque<SlicingCriterion> deque;
    private final HashSet<SlicingCriterion> tempSlicingCriteria;

    public ProgramSlicer() {
        codeInspector = CodeInspector.getInstance();
        slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        sliceDatabase = SliceDatabase.getInstance();
        sliceMerger = SliceMerger.getInstance();

        deque = new LinkedList<>();
        tempSlicingCriteria = new HashSet<>();
    }

    public static ProgramSlicer getInstance() {
        return ProgramSlicer.Holder.instance;
    }

    public void sliceStatements(SlicingCriterion slicingCriterion) {
        String leafId = String.valueOf(slicingCriterion.hashCode());
        sliceMerger.addNode(leafId, leafId, "leaf", 0);

        deque.add(slicingCriterion);

        while (!deque.isEmpty()) {
            SlicingCriterion sc = deque.poll();
            sliceStatement(sc);
        }
    }

    private void sliceStatement(SlicingCriterion slicingCriterion) {
        String nodeId = String.valueOf(slicingCriterion.hashCode());
        if (sliceDatabase.isSliceExist(nodeId, false)) {
            return;
        }

        String callerName = slicingCriterion.getCallerName();
        String targetStatement = slicingCriterion.getTargetStatement();
        int startUnitIndex = slicingCriterion.getTargetUnitIndex();
        HashMap<String, ValueBox> oldTargetVariableMap = slicingCriterion.getTargetVariableMap();
        ArrayList<String> oldTargetVariables = new ArrayList<>(oldTargetVariableMap.keySet());

        ArrayList<Unit> wholeUnits = codeInspector.getWholeUnits(callerName);
        wholeUnits = new ArrayList<>(wholeUnits);
        Collections.reverse(wholeUnits);
        int wholeUnitCount = wholeUnits.size();
        Unit startUnit = wholeUnits.get(startUnitIndex);
        int startUnitType = getUnitType(startUnit);
        int startLineNum = wholeUnitCount - startUnitIndex;
        HashMap<Integer, ArrayList<Unit>> switchTargetUnitMap = codeInspector.getTargetUnits(callerName);
        Set<Map.Entry<Integer, ArrayList<Unit>>> switchTargetUnitSet = (switchTargetUnitMap == null) ? null : switchTargetUnitMap.entrySet();

        HashMap<String, ValueBox> newTargetVariableMap = new HashMap<>(oldTargetVariableMap);
        ArrayList<Unit> whileUnits = new ArrayList<>();
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
                Unit targetUnit = getTargetUnit(unit, unitType);
                int targetUnitIndex = wholeUnits.indexOf(targetUnit);
                if (targetUnit != null && startUnitIndex > targetUnitIndex) {
                    continue;
                }

                if (whileUnits.contains(unit)) {
                    whileUnits.remove(unit);
                    continue;
                }

                ArrayList<ValueBox> conditionValues = getConditionValues(unit, unitType);
                addTargetVariables(conditionValues, newTargetVariableMap);

                units.add(unit);
                addLine(unit, unitType, callerName, lineNum, slice);
                continue;
            } else if (unitType == GOTO) {
                Unit targetUnit1 = getTargetUnit(unit, unitType);
                int targetUnitType1 = getUnitType(targetUnit1);
                if (targetUnitType1 != IF) {
                    units.add(unit);
                    addLine(unit, unitType, callerName, lineNum, slice);
                    continue;
                }

                Unit targetUnit2 = getTargetUnit(targetUnit1, IF);
                int targetUnitType2 = getUnitType(targetUnit2);
                if (targetUnitType2 != NEW_EXCEPTION) {
                    whileUnits.add(targetUnit1);
                }

                continue;
            } else if (unitType == SWITCH) {
                ValueBox valueBox = getSwitchValueBox(unit, unitType);
                if (valueBox != null) {
                    addTargetVariable(valueBox, newTargetVariableMap);
                }

                units.add(unit);
                addLine(unit, unitType, callerName, lineNum, slice);
                continue;
            }

            List<ValueBox> useAndDefBoxes = unit.getUseAndDefBoxes();
            List<String> valueStrings = convertToStrings(useAndDefBoxes);
            HashSet<String> retainVariables = new HashSet<>(valueStrings);
            retainVariables.retainAll(newTargetVariableMap.keySet());
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
                    ArrayList<ValueBox> paramValues = getParamValues(unit, unitType);

                    if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                        ValueBox oldValueBox = paramValues.get(2);
                        String oldValueStr = getValueStr(oldValueBox);
                        if (!retainVariables.contains(oldValueStr)) {
                            continue;
                        }

                        newTargetVariableMap.remove(oldValueStr);
                        ValueBox newValueBox = paramValues.get(0);
                        addTargetVariable(newValueBox, newTargetVariableMap);
                    } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                        ValueBox oldValueBox = paramValues.get(0);
                        if (!newTargetVariableMap.containsValue(oldValueBox)) {
                            continue;
                        }

                        ValueBox newValueBox = paramValues.get(1);
                        addTargetVariable(newValueBox, newTargetVariableMap);
                    } else {
                        ValueBox localValueBox = getLocalValueBox(unit, unitType);
                        if (localValueBox != null) {
                            addTargetVariable(localValueBox, newTargetVariableMap);
                        }

                        ArrayList<String> paramTypes = getParamTypes(signature);
                        addTargetVariables(paramTypes, paramValues, newTargetVariableMap);
                    }

                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_INTERFACE_INVOKE:
                case ASSIGN_SPECIAL_INVOKE: {
                    Value value = getLeftValue(unit, unitType);
                    String valueStr = convertToStr(value);
                    if (retainVariables.contains(valueStr)) {
                        newTargetVariableMap.remove(valueStr);
                    }

                    String signature = getSignature(unitStr);
                    ArrayList<String> paramTypes = getParamTypes(signature);
                    ArrayList<ValueBox> paramValues = getParamValues(unit, unitType);

                    ValueBox localValueBox = getLocalValueBox(unit, unitType);
                    if (localValueBox == null) {
                        addTargetVariables(paramTypes, paramValues, newTargetVariableMap);
                    } else {
                        addTargetVariable(localValueBox, newTargetVariableMap);
                    }

                    handleAssignInvokeUnit(nodeId, signature);
                    break;
                }

                case PARAMETER: {
                    String paramNum = getParamNum(unit, unitType);
                    newParamNums.add(0, paramNum);
                    break;
                }

                case NEW_INSTANCE:
                case NEW_ARRAY:
                case ASSIGN_VARIABLE_CONSTANT: {
                    Value leftValue = getLeftValue(unit, unitType);
                    String leftValueStr = convertToStr(leftValue);
                    if (!retainVariables.contains(leftValueStr)) {
                        continue;
                    }

                    newTargetVariableMap.remove(leftValueStr);
                    break;
                }

                case ASSIGN_VARIABLE_VARIABLE: {
                    Value leftValue = getLeftValue(unit, unitType);
                    String leftValueStr = convertToStr(leftValue);
                    if (!retainVariables.contains(leftValueStr)) {
                        continue;
                    }

                    newTargetVariableMap.remove(leftValueStr);

                    ValueBox rightValueBox = getRightValueBox(unit, unitType);
                    String rightValueStr = getValueStr(rightValueBox);
                    newTargetVariableMap.put(rightValueStr, rightValueBox);
                    break;
                }

                case ASSIGN_VARIABLE_SIGNATURE: {
                    if (startUnitType == ASSIGN_SIGNATURE_VARIABLE) {
                        Value leftValue = getLeftValue(unit, unitType);
                        String leftValueStr = convertToStr(leftValue);
                        newTargetVariableMap.remove(leftValueStr);

                        ValueBox rightValueBox = getRightValueBox(unit, unitType);
                        String rightValueStr = getValueStr(rightValueBox);
                        newTargetVariableMap.put(rightValueStr, rightValueBox);
                    }

                    String signature = getSignature(unitStr);
                    handleAssignVariableSignatureUnit(callerName, nodeId, signature);
                    break;
                }

                case CAST:
                case LENGTH_OF: {
                    Value leftValue = getLeftValue(unit, unitType);
                    String leftValueStr = convertToStr(leftValue);
                    if (!retainVariables.contains(leftValueStr)) {
                        continue;
                    }

                    newTargetVariableMap.remove(leftValueStr);

                    ValueBox rightValueBox = getRightInternalValue(unit, unitType);
                    String rightValueStr = getValueStr(rightValueBox);
                    newTargetVariableMap.put(rightValueStr, rightValueBox);
                    break;
                }

                case RETURN_VALUE: {
                    ValueBox rightValueBox = getRightValueBox(unit, unitType);
                    String rightValueStr = getValueStr(rightValueBox);

                    if (retainVariables.contains(rightValueStr)) {
                        continue; // ignore return statement
                    } else {
                        break;
                    }
                }

                default: {
                    break;
                }
            }

            units.add(unit);
            addLine(unit, unitType, callerName, lineNum, slice);
        }

        handleParameterUnit(nodeId, callerName, newParamNums);

        deque.addAll(tempSlicingCriteria);
        tempSlicingCriteria.clear();

        sliceDatabase.insert(nodeId, callerName, targetStatement, startUnitIndex, oldTargetVariables, slice);
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

    private void addTargetVariable(ValueBox valueBox, HashMap<String, ValueBox> newTargetVariableMap) {
        Value value = valueBox.getValue();
        String valueStr = value.toString();
        if (!isVariableStr(valueStr)) {
            return;
        }

        newTargetVariableMap.put(valueStr, valueBox);
    }

    private void addTargetVariables(ArrayList<String> paramTypes, ArrayList<ValueBox> valueBoxes, HashMap<String, ValueBox> newTargetVariableMap) {
        int size = paramTypes.size();
        for (int i = 0; i < size; i++) {
            String paramType = paramTypes.get(i);
            if (!paramType.equals("int") && !paramType.contains("char") && !paramType.equals("java.lang.String") && !paramType.contains("byte")) {
                continue;
            }

            ValueBox valueBox = valueBoxes.get(i);
            addTargetVariable(valueBox, newTargetVariableMap);
        }
    }

    private void addTargetVariables(ArrayList<ValueBox> valueBoxes, HashMap<String, ValueBox> newTargetVariableMap) {
        for (ValueBox vb : valueBoxes) {
            addTargetVariable(vb, newTargetVariableMap);
        }
    }

    private void handleAssignInvokeUnit(String parentId, String calleeName) {
        Node parent = sliceMerger.getNode(parentId);
        int level = (int) parent.getAttribute("level");
        if (level == LOWER_LEVEL) {
            return;
        } else {
            level--;
        }

        ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "return", RETURN_VALUE, null);
        for (SlicingCriterion sc : slicingCriteria) {
            String childId = String.valueOf(sc.hashCode());
            Node child = sliceMerger.addNode(childId, childId, "child", level);
            sliceMerger.addEdge(parent, child, DOWNWARD);

            tempSlicingCriteria.add(sc);
        }
    }

    private void handleAssignVariableSignatureUnit(String oldCallerName, String siblingId, String targetStatement) {
        Node oldCaller = codeInspector.getNode(oldCallerName);
        Node sibling = sliceMerger.getNode(siblingId);
        int level = (int) sibling.getAttribute("level");
        String newSiblingId = String.valueOf(targetStatement.hashCode());
        Node newSibling = sliceMerger.getNode(newSiblingId);
        if (newSibling == null) {
            newSibling = sliceMerger.addNode(newSiblingId, newSiblingId, "sibling", level);
            sliceMerger.addEdge(sibling, newSibling, NONE);
        }

        level++;

        Node valueNode = codeInspector.getNode(targetStatement);
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

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(newCallerName, targetStatement, ASSIGN, null);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId = String.valueOf(sc.hashCode());
                Node parent = sliceMerger.addNode(parentId, parentId, "parent", level);
                sliceMerger.addEdge(newSibling, parent, UPWARD);

                tempSlicingCriteria.add(sc);
            }
        }
    }

    private void handleParameterUnit(String childId, String calleeName, ArrayList<String> paramNums) {
        if (paramNums.isEmpty()) {
            return;
        }

        Node child = sliceMerger.getNode(childId);
        int level = (int) child.getAttribute("level");
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
                Node parent = sliceMerger.addNode(parentId, parentId, "parent", level);
                sliceMerger.addEdge(child, parent, UPWARD);

                tempSlicingCriteria.add(sc);
            }
        }
    }

    private void addLine(Unit unit, int unitType, String callerName, int lineNum, ArrayList<Document> slice) {
        Document line = new Document();
        line.put("unit", unit.toString());
        line.put("unitType", unitType);
        line.put("callerName", callerName);
        line.put("lineNum", lineNum);

        slice.add(0, line);
    }

    private static class Holder {
        private static final ProgramSlicer instance = new ProgramSlicer();
    }
}