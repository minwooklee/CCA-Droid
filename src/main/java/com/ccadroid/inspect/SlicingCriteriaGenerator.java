package com.ccadroid.inspect;

import com.ccadroid.util.soot.Soot;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.ccadroid.check.RuleConstants.SLICING_SIGNATURES;
import static com.ccadroid.util.soot.SootUnit.*;

public class SlicingCriteriaGenerator {
    private final ApkParser apkParser;
    private final CodeInspector codeInspector;

    public SlicingCriteriaGenerator() {
        apkParser = ApkParser.getInstance();
        codeInspector = CodeInspector.getInstance();
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
            String targetSignature = sc.getTargetSignature();
            if (!isCorrectSignature(targetSignature)) {
                continue;
            }

            Node callee = codeInspector.getNode(targetSignature);
            if (callee == null) {
                continue;
            }

            ArrayList<String> targetParamNums = sc.getTargetParamNums();

            Stream<Edge> stream = callee.edges();
            List<Edge> edges = stream.collect(Collectors.toList());
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

                ArrayList<SlicingCriterion> criteria = createSlicingCriteria(callerName, targetSignature, INVOKE, targetParamNums);
                slicingCriteria.addAll(criteria);
            }
        }

        return slicingCriteria;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(String callerName, String targetSignature, int targetUnitType, ArrayList<String> targetParamNums) {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();

        String returnType = null;
        if (targetUnitType == ASSIGN) {
            returnType = getReturnType(targetSignature);
        } else if (targetUnitType == RETURN_VALUE) {
            returnType = getReturnType(callerName);
        }

        if (returnType != null && (!returnType.equals("int") && !returnType.contains("char") && !returnType.contains("String") && !returnType.contains("byte"))) {
            return slicingCriteria;
        }

        ArrayList<Unit> wholeUnits = codeInspector.getWholeUnits(callerName);
        if (wholeUnits == null || wholeUnits.isEmpty()) {
            return slicingCriteria;
        }

        wholeUnits = new ArrayList<>(wholeUnits);
        Collections.reverse(wholeUnits);

        int wholeUnitCount = wholeUnits.size();
        for (int i = wholeUnitCount - 1; i > 0; i--) {
            Unit unit = wholeUnits.get(i);
            String unitStr = unit.toString();
            if (!(unitStr.contains(targetSignature))) {
                continue;
            }

            int unitType = getUnitType(unit);
            boolean isAssign = (targetUnitType == ASSIGN && (unitType == ASSIGN_SIGNATURE_VARIABLE));
            boolean isInvoke = (targetUnitType == INVOKE && (unitType & INVOKE) == INVOKE);
            boolean isReturn = (targetUnitType == RETURN_VALUE && unitType == RETURN_VALUE);
            if (!isAssign && !isInvoke && !isReturn) {
                continue;
            }

            HashSet<Value> targetVariables = new HashSet<>();

            switch (unitType) {
                case ASSIGN_SIGNATURE_VARIABLE:
                case RETURN_VALUE: {
                    Value value = getRightValue(unit, unitType);
                    targetVariables.add(value);
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
                    ArrayList<Value> paramValues = getParamValues(unit, unitType);
                    if (targetParamNums.isEmpty() && !paramValues.isEmpty()) {
                        continue;
                    }

                    if (targetParamNums.contains("-1")) {
                        Value value = getLocalValue(unit, unitType);
                        targetVariables.add(value);
                    }

                    ArrayList<String> tempParamNums = new ArrayList<>(targetParamNums);
                    for (String j : tempParamNums) { // for multiple paramNums
                        if (j.equals("-1")) {
                            continue;
                        }

                        int paramNum = Integer.parseInt(j);
                        String type = paramTypes.get(paramNum);
                        if (!type.equals("int") && !type.contains("String") && !type.contains("byte")) {
                            continue;
                        }

                        Value value = paramValues.get(paramNum);
                        targetVariables.add(value);
                    }

                    break;
                }
            }

            if (targetVariables.isEmpty() || isDuplicatedCriterion(targetSignature, targetVariables, slicingCriteria)) {
                continue;
            }

            SlicingCriterion slicingCriterion = new SlicingCriterion();
            slicingCriterion.setCallerName(callerName);
            slicingCriterion.setTargetSignature(targetSignature);
            slicingCriterion.setTargetParamNums(targetParamNums);
            slicingCriterion.setTargetUnitIndex(i);
            slicingCriterion.setTargetVariables(new HashSet<>(targetVariables));
            if (slicingCriteria.contains(slicingCriterion)) {
                continue;
            }

            slicingCriteria.add(slicingCriterion);
        }

        return slicingCriteria;
    }

    private ArrayList<SlicingCriterion> getSlicingCandidates(File ruleFileDir) {
        ArrayList<SlicingCriterion> candidates = new ArrayList<>();

        File[] ruleFiles = ruleFileDir.listFiles();
        if (ruleFiles == null) {
            return candidates;
        }

        for (File f : ruleFiles) {
            try {
                if (f.isDirectory()) {
                    continue;
                }

                String path = f.getAbsolutePath();
                InputStream inputStream = Files.newInputStream(Paths.get(path));
                JSONTokener tokenizer = new JSONTokener(inputStream);
                JSONObject root = new JSONObject(tokenizer);
                JSONObject signatures = root.getJSONObject(SLICING_SIGNATURES);
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
                    slicingCriterion.setTargetSignature(signature);
                    slicingCriterion.setTargetParamNums(paramNums);
                    candidates.add(slicingCriterion);
                }

                inputStream.close();
            } catch (IOException | JSONException ignored) {
                System.out.println("[*] ERROR: Cannot import rule file: " + f.getName());
            }
        }

        return candidates;
    }

    private boolean isCorrectSignature(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = Soot.getSootClass(className);
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

    private boolean isDuplicatedCriterion(String targetSignature, HashSet<Value> targetVariables, ArrayList<SlicingCriterion> slicingCriteria) {
        for (SlicingCriterion sc : slicingCriteria) {
            String signature = sc.getTargetSignature();
            HashSet<Value> variables = sc.getTargetVariables();
            if (targetSignature.equals(signature) && targetVariables.containsAll(variables)) {
                return true;
            }
        }

        return false;
    }

    private static class Holder {
        private static final SlicingCriteriaGenerator instance = new SlicingCriteriaGenerator();
    }
}