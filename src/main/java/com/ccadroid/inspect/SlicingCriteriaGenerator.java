package com.ccadroid.inspect;

import com.ccadroid.model.SlicingCriterion;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import soot.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Stream;

import static com.ccadroid.util.soot.SootUnit.*;
import static java.lang.Integer.parseInt;
import static java.util.Collections.reverse;
import static java.util.stream.Collectors.toList;

public class SlicingCriteriaGenerator {
    private final ApkParser apkParser;
    private final CodeInspector codeInspector;
    private final HashMap<String, SlicingCriterion> slicingCriterionMap;

    public SlicingCriteriaGenerator() {
        apkParser = ApkParser.getInstance();
        codeInspector = CodeInspector.getInstance();
        slicingCriterionMap = new HashMap<>();
    }

    public static SlicingCriteriaGenerator getInstance() {
        return SlicingCriteriaGenerator.Holder.instance;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(File ruleFileDir) {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();
        HashMap<String, ArrayList<ArrayList<String>>> listOfCallersMap = new HashMap<>();

        String packageName = apkParser.getPackageName();
        String appClassName = apkParser.getAppClassName();
        ArrayList<String> appComponents = apkParser.getAppComponents();

        ArrayList<SlicingCriterion> candidates = getSlicingCandidates(ruleFileDir);
        for (SlicingCriterion sc : candidates) {
            String targetStatement = sc.getTargetStatement();
            Node callee = codeInspector.getNode(targetStatement);
            if (!isCorrectSignature(targetStatement) || callee == null) {
                continue;
            }

            ArrayList<String> targetParamNums = sc.getTargetParamNums();

            Stream<Edge> stream = callee.edges();
            List<Edge> edges = stream.collect(toList());
            for (Edge e : edges) {
                Node caller = e.getSourceNode();
                String callerName = caller.getId();
                ArrayList<ArrayList<String>> listOfCallers = listOfCallersMap.get(callerName);
                if (listOfCallers != null) {
                    continue;
                }

                listOfCallers = codeInspector.traverseCallers(callerName, true);
                setReachableCallers(packageName, appClassName, appComponents, listOfCallers);
                listOfCallersMap.put(callerName, listOfCallers);

                ArrayList<SlicingCriterion> criteria = createSlicingCriteria(caller, targetStatement, INVOKE, targetParamNums);
                slicingCriteria.addAll(criteria);
            }
        }

        return slicingCriteria;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(Node caller, String targetStatement, int targetUnitType, ArrayList<String> targetParamNums) {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();
        String callerName = caller.getId();

        String returnType = null;
        if (targetUnitType == ASSIGN) {
            returnType = getReturnType(targetStatement);
        } else if (targetUnitType == RETURN_VALUE) {
            returnType = getReturnType(callerName);
        }

        if (returnType != null && (!returnType.equals("int") && !returnType.equals("java.lang.String") && !returnType.equals("byte") && !returnType.equals("bytes[]"))) {
            return slicingCriteria;
        }

        SootMethod sootMethod = codeInspector.getSootMethod(callerName); // avoid built-in library
        if (sootMethod == null) {
            return slicingCriteria;
        }

        Body body = sootMethod.retrieveActiveBody();
        UnitPatchingChain chain = body.getUnits();
        ArrayList<Unit> wholeUnits = new ArrayList<>(chain);
        reverse(wholeUnits);

        int wholeUnitsSize = wholeUnits.size();
        for (int i = 0; i < wholeUnitsSize; i++) {
            Unit unit = wholeUnits.get(i);
            String unitStr = unit.toString();
            if (!(unitStr.contains(targetStatement))) {
                continue;
            }

            int unitType = getUnitType(unit);
            boolean isAssign = (targetUnitType == ASSIGN && (unitType == ASSIGN_SIGNATURE_VARIABLE));
            boolean isInvoke = (targetUnitType == INVOKE && (unitType & INVOKE) == INVOKE);
            boolean isReturn = (targetUnitType == RETURN_VALUE && unitType == RETURN_VALUE);
            if (!isAssign && !isInvoke && !isReturn) {
                continue;
            }

            HashMap<String, ValueBox> targetVariableMap = new HashMap<>();

            switch (unitType) {
                case ASSIGN_SIGNATURE_VARIABLE:
                case RETURN_VALUE: {
                    ValueBox valueBox = getRightValueBox(unit, unitType);
                    if (valueBox != null) {
                        Value value = valueBox.getValue();
                        String valueStr = value.toString();
                        targetVariableMap.put(valueStr, valueBox);
                    }

                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_SPECIAL_INVOKE:
                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case SPECIAL_INVOKE: {
                    String signature = getSignature(unitStr);
                    ArrayList<String> paramTypes = getParamTypes(signature);
                    ArrayList<ValueBox> paramValues = getParamValues(unit, unitType);
                    if (targetParamNums.isEmpty() && !paramValues.isEmpty()) {
                        continue;
                    }

                    if (targetParamNums.contains("-1")) {
                        ValueBox valueBox = getLocalValueBox(unit, unitType);
                        if (valueBox != null) {
                            Value value = valueBox.getValue();
                            String valueStr = value.toString();
                            targetVariableMap.put(valueStr, valueBox);
                        }
                    }

                    ArrayList<String> tempParamNums = new ArrayList<>(targetParamNums);
                    for (String j : tempParamNums) { // for multiple paramNums
                        if (j.equals("-1")) {
                            continue;
                        }

                        int paramNum = parseInt(j);
                        String type = paramTypes.get(paramNum);
                        if (!type.equals("int") && !type.equals("java.lang.String") && !type.equals("byte") && !type.equals("bytes[]")) {
                            continue;
                        }

                        ValueBox valueBox = paramValues.get(paramNum);
                        Value value = valueBox.getValue();
                        String valueStr = value.toString();
                        targetVariableMap.put(valueStr, valueBox);
                    }

                    break;
                }
            }

            if (targetVariableMap.isEmpty()) {
                continue;
            }

            SlicingCriterion slicingCriterion = new SlicingCriterion();
            slicingCriterion.setCaller(caller);
            slicingCriterion.setTargetStatement(targetStatement);
            slicingCriterion.setTargetParamNums(targetParamNums);
            slicingCriterion.setTargetUnitIndex(i);
            slicingCriterion.setTargetVariableMap(new HashMap<>(targetVariableMap));
            slicingCriterion.setWholeUnits(wholeUnits);
            if (slicingCriteria.contains(slicingCriterion)) {
                continue;
            }

            String hashCode = String.valueOf(slicingCriterion.hashCode());
            slicingCriterionMap.put(hashCode, slicingCriterion);

            slicingCriteria.add(slicingCriterion);
        }

        return slicingCriteria;
    }

    public SlicingCriterion getSlicingCriterion(String hashCode) {
        return slicingCriterionMap.get(hashCode);
    }

    private ArrayList<SlicingCriterion> getSlicingCandidates(File ruleFileDir) {
        ArrayList<SlicingCriterion> candidates = new ArrayList<>();

        File[] ruleFiles = ruleFileDir.listFiles();
        if (ruleFiles == null) {
            return candidates;
        }

        for (File f : ruleFiles) {
            try {
                String path = f.getAbsolutePath();
                InputStream inputStream = Files.newInputStream(Paths.get(path));
                JSONTokener tokenizer = new JSONTokener(inputStream);
                JSONObject root = new JSONObject(tokenizer);
                JSONObject signatures = root.getJSONObject("signatures");
                if (signatures == null) {
                    continue;
                }

                Iterator<String> keys = signatures.keys();
                while (keys.hasNext()) {
                    String signature = keys.next();
                    ArrayList<String> paramNums = new ArrayList<>();
                    JSONArray jsonArr = signatures.getJSONArray(signature);
                    for (int i = 0; i < jsonArr.length(); i++) {
                        int paramNum = jsonArr.getInt(i);
                        paramNums.add(String.valueOf(paramNum));
                    }

                    SlicingCriterion slicingCriterion = new SlicingCriterion();
                    slicingCriterion.setTargetStatement(signature);
                    slicingCriterion.setTargetParamNums(paramNums);
                    candidates.add(slicingCriterion);
                }

                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return candidates;
    }

    private boolean isCorrectSignature(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = Scene.v().getSootClass(className);
        List<SootMethod> methods = sootClass.getMethods();
        String methodsStr = methods.toString();

        return !sootClass.isPhantomClass() || !methodsStr.contains(signature);
    }

    private void setReachableCallers(String packageName, String appClassName, ArrayList<String> appComponents, ArrayList<ArrayList<String>> listOfCallers) {
        ArrayList<ArrayList<String>> targets = new ArrayList<>();

        for (ArrayList<String> l : listOfCallers) {
            boolean flag = true;

            for (String c : l) {
                String className = getClassName(c);
                className = className.split("\\$")[0];
                if (className.contains(packageName) || className.equals(appClassName) || appComponents.contains(className)) {
                    flag = false;
                    break;
                }

                HashSet<String> tempSet1;
                HashSet<String> tempSet2;
                HashSet<String> set1 = new HashSet<>(Arrays.asList(packageName.split("\\.")));
                HashSet<String> set2 = new HashSet<>(Arrays.asList(className.split("\\.")));
                if (set1.size() <= set2.size()) {
                    tempSet1 = set1;
                    tempSet2 = set2;
                } else {
                    tempSet1 = set2;
                    tempSet2 = set1;
                }

                int count = 0;
                for (String s : tempSet1) {
                    if (tempSet2.contains(s)) {
                        count++;
                    }
                }

                if (count > 1) {
                    flag = false;
                    break;
                }
            }

            if (flag) {
                targets.add(l);
            }
        }

        listOfCallers.removeAll(targets);
    }

    private static class Holder {
        private static final SlicingCriteriaGenerator instance = new SlicingCriteriaGenerator();
    }
}