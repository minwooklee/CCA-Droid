package com.ccadroid.check;

import com.ccadroid.slice.SliceDatabase;
import com.ccadroid.util.soot.SootUnit;
import com.mongodb.client.FindIterable;
import org.bson.Document;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.mariuszgromada.math.mxparser.Expression;
import org.mariuszgromada.math.mxparser.License;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ccadroid.check.RuleConstants.*;
import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class RuleChecker {
    private static final Pattern ALGORITHM_PATTERN = Pattern.compile("^(?i)((DES|AES|RSA)|(DES|AES|RSA)/+.*|(HMAC\\d+))$");
    private static final Pattern NUMBER_PATTERN = Pattern.compile("^-*\\d*$");
    private final SliceDatabase sliceDatabase;
    private final ArrayList<JSONObject> rules;

    public RuleChecker() {
        sliceDatabase = SliceDatabase.getInstance();
        rules = new ArrayList<>();

        License.iConfirmNonCommercialUse("CCA-Droid");
    }

    public static RuleChecker getInstance() {
        return RuleChecker.Holder.instance;
    }

    public void loadRules(File ruleFileDir) {
        File[] ruleFiles = ruleFileDir.listFiles();
        if (ruleFiles == null) {
            return;
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
                rules.add(root);

                inputStream.close();
            } catch (IOException | JSONException ignored) {
                System.out.println("[*] ERROR: Cannot import rule file:" + f.getPath());
            }
        }
    }

    public void checkRules() {
        FindIterable<Document> result = sliceDatabase.selectAll("{'" + NODE_ID + "': {$exists: false}, '" + GROUP_ID + "': {$exists: true}}");
        HashMap<JSONObject, ArrayList<Document>> sliceMap = classifySlices(result);
        if (sliceMap.isEmpty()) {
            return;
        }

        Set<Map.Entry<JSONObject, ArrayList<Document>>> entries = sliceMap.entrySet();
        for (Map.Entry<JSONObject, ArrayList<Document>> e : entries) {
            JSONObject root = e.getKey();
            ArrayList<Document> slice = e.getValue();

            checkRules(root, slice, INSECURE_RULE);
            checkRules(root, slice, SECURE_RULE);
        }
    }

    private void checkRules(JSONObject root, ArrayList<Document> slice, String ruleName) {
        if (!root.has(ruleName)) {
            return;
        }

        JSONObject rule = root.getJSONObject(ruleName);
        if (rule.has(TARGET_CONSTANT)) {
            checkConstants(slice, rule);
        }

        if (rule.has(TARGET_SIGNATURES)) {
            checkFunctions(slice, rule);
        }

        if (rule.has(TARGET_SCHEME_TYPES)) {
            checkMACScheme(slice, rule);
        }
    }

    private HashMap<JSONObject, ArrayList<Document>> classifySlices(FindIterable<Document> result) {
        HashMap<JSONObject, ArrayList<Document>> map = new HashMap<>();

        for (Document s : result) {
            String topId = s.getString(GROUP_ID);
            String targetSignature = s.getString(TARGET_SIGNATURE);
            List<String> targetParamNums = s.getList(TARGET_PARAM_NUMS, String.class);
            String targetParamNumStr = targetParamNums.toString();

            for (JSONObject r : rules) {
                ArrayList<Document> targetSlices = map.containsKey(r) ? map.get(r) : new ArrayList<>();
                ArrayList<Document> tempSlices = new ArrayList<>();

                JSONObject obj = r.getJSONObject(SLICING_SIGNATURES);
                Map<String, Object> objAsMap = obj.toMap();
                Set<Map.Entry<String, Object>> entries = objAsMap.entrySet();
                for (Map.Entry<String, Object> e : entries) {
                    String signature = e.getKey();
                    Object paramNums = e.getValue();
                    if (!targetSignature.equals(signature)) {
                        continue;
                    }

                    String paramNumStr = paramNums.toString();
                    if (!(targetParamNumStr.equals(paramNumStr))) {
                        continue;
                    }

                    FindIterable<Document> tempSlice = sliceDatabase.selectAll("{'" + GROUP_ID + "': '" + topId + "', '" + USED + "': {$exists: false}}");
                    for (Document d : tempSlice) {
                        List<Document> content = d.getList(CONTENT, Document.class);
                        if (tempSlices.containsAll(content)) {
                            continue;
                        }

                        tempSlices.addAll(content);
                        if (!targetSlices.contains(d)) {
                            targetSlices.add(0, d);
                        }
                    }
                }

                if (!targetSlices.isEmpty()) {
                    map.put(r, targetSlices);
                }
            }
        }

        return map;
    }

    private void checkConstants(ArrayList<Document> slices, JSONObject rule) {
        String ruleId = rule.getString(RULE_ID);
        String description = rule.getString(DESCRIPTION);
        String regex = rule.getString(TARGET_CONSTANT);
        Pattern targetPattern = Pattern.compile(regex);
        String length = rule.has(TARGET_CONSTANT_LEN) ? rule.getString(TARGET_CONSTANT_LEN) : null;
        String size = rule.has(TARGET_CONSTANT_SIZE) ? rule.getString(TARGET_CONSTANT_SIZE) : null;

        for (Document s : slices) {
            List<Document> slice = s.getList(CONTENT, Document.class);
            for (Document l : slice) {
                if (!l.containsKey(CONSTANTS)) {
                    continue;
                }

                List<String> constants = l.getList(CONSTANTS, String.class);
                for (String c : constants) {
                    Matcher matcher1 = ALGORITHM_PATTERN.matcher(c);
                    if (matcher1.matches()) {
                        continue;
                    }

                    Matcher matcher2 = NUMBER_PATTERN.matcher(c);
                    if (matcher2.matches()) {
                        continue;
                    }

                    Matcher matcher3 = targetPattern.matcher(c);
                    if (!matcher3.matches()) {
                        continue;
                    }

                    if (length != null) {
                        Expression e = new Expression(c.length() + length);
                        if (e.calculate() == 0) {
                            continue;
                        }
                    }

                    if (size != null) {
                        Expression e = new Expression(Integer.parseInt(c) + length);
                        if (e.calculate() == 0) {
                            continue;
                        }
                    }

                    String nodeId = s.containsKey(NODE_ID) ? s.getString(NODE_ID) : s.getString(GROUP_ID);
                    String callerName = l.getString(CALLER_NAME);
                    String unitStr = l.getString(UNIT_STRING);

                    printResult(ruleId, description, nodeId, callerName, unitStr);
                    break;
                }
            }
        }
    }

    private void checkFunctions(ArrayList<Document> slices, JSONObject rule) {
        String ruleId = rule.getString(RULE_ID);
        String description = rule.getString(DESCRIPTION);
        JSONArray arr = rule.getJSONArray(TARGET_SIGNATURES);
        List<Object> arrAsList = arr.toList();

        for (Document s : slices) {
            List<Document> slice = s.getList(CONTENT, Document.class);
            for (Document l : slice) {
                int unitType = l.getInteger(UNIT_TYPE);
                if ((unitType & INVOKE) != INVOKE) {
                    continue;
                }

                String unitStr = l.getString(UNIT_STRING);
                String signature = SootUnit.getSignature(unitStr);
                if (arrAsList.contains(signature)) {
                    String nodeId = s.containsKey(NODE_ID) ? s.getString(NODE_ID) : s.getString(GROUP_ID);
                    String callerName = l.getString(CALLER_NAME);

                    printResult(ruleId, description, nodeId, callerName, unitStr);
                }
            }
        }
    }

    private void checkMACScheme(ArrayList<Document> slices, JSONObject rule) {
        String ruleId = rule.getString(RULE_ID);
        String description = rule.getString(DESCRIPTION);
        JSONArray types = rule.getJSONArray(TARGET_SCHEME_TYPES);
        List<Object> typesAsList = types.toList();

        for (Document s : slices) {
            List<Document> slice = s.getList(CONTENT, Document.class);
            int sliceLen = slice.size();
            ArrayList<String> targetParamNums = new ArrayList<>();
            HashSet<String> targetVariables = new HashSet<>();

            for (int i = sliceLen; i > 0; i--) {
                Document line = slice.get(i - 1);
                String unitStr = line.getString(UNIT_STRING);
                int unitType = line.getInteger(UNIT_TYPE);
                if (unitType == PARAMETER) {
                    String paramNum = getParamNum(unitStr, unitType);
                    targetParamNums.add(paramNum);
                    continue;
                }

                if ((unitType & INVOKE) != INVOKE) {
                    continue;
                }

                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("javax.crypto.Cipher") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    if (targetVariables.isEmpty() && !paramValues.isEmpty()) {
                        targetVariables.add(paramValues.get(0));
                        continue;
                    }

                    String targetVariable = getTargetVariable(unitStr);
                    if ((targetVariables.contains(targetVariable) && typesAsList.contains(ENCRYPT_THEN_MAC)) || (!targetVariables.contains(targetVariable) && typesAsList.contains(ENCRYPT_AND_MAC))) {
                        String nodeId = s.containsKey(NODE_ID) ? s.getString(NODE_ID) : s.getString(GROUP_ID);
                        String callerName = line.getString(CALLER_NAME);

                        printResult(ruleId, description, nodeId, callerName, unitStr);
                        break;
                    }
                } else if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    if (!targetVariables.contains(paramValues.get(2))) {
                        continue;
                    }

                    targetVariables.remove(paramValues.get(2));
                    targetVariables.add(paramValues.get(0));
                } else if (className.equals("javax.crypto.Mac") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    if (targetVariables.isEmpty() && !paramValues.isEmpty()) {
                        targetVariables.add(paramValues.get(0));
                        continue;
                    }

                    String targetValueStr = getTargetVariable(unitStr);
                    if (targetVariables.contains(targetValueStr)) {
                        String nodeId = s.containsKey(NODE_ID) ? s.getString(NODE_ID) : s.getString(GROUP_ID);
                        String callerName = line.getString(CALLER_NAME);

                        printResult(ruleId, description, nodeId, callerName, unitStr);
                        break;
                    }
                } else if (!targetParamNums.isEmpty()) {
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    for (String n : targetParamNums) {
                        int index = Integer.parseInt(n);
                        String value = paramValues.get(index);
                        targetVariables.add(value);
                    }

                    targetParamNums.clear();
                }
            }
        }
    }

    private String getTargetVariable(String unitStr) {
        String variable = null;

        if (unitStr.contains(" = ")) {
            String[] strArr = unitStr.split(" = ");
            variable = strArr[0];
        } else {
            ArrayList<String> paramValues = getParamValues(unitStr);
            if (!paramValues.isEmpty()) {
                variable = paramValues.get(0);
            }
        }

        return variable;
    }

    private String getTargetSignature(String nodeId) {
        String query = "{'" + NODE_ID + "': '" + nodeId + "'}, {'" + GROUP_ID + "': '" + nodeId + "'}";
        if (sliceDatabase.selectCount(query) == 0) {
            return null;
        }

        FindIterable<Document> result = sliceDatabase.selectAll(query);
        Document slice = result.first();

        return (slice == null) ? null : slice.getString(TARGET_SIGNATURE);
    }

    private void printResult(String ruleId, String description, String nodeId, String callerName, String unitStr) {
        String targetSignature = getTargetSignature(nodeId);

        System.out.println();
        System.out.println("=======================================");
        System.out.println("[*] Rule ID: " + ruleId);
        System.out.println("[*] Description: " + description);
        System.out.println("[*] Target signature: " + targetSignature);
        System.out.println("[*] Caller name: " + callerName);
        System.out.println("[*] Target line:");
        System.out.println(unitStr);
        System.out.println("=======================================");
    }

    private static class Holder {
        private static final RuleChecker instance = new RuleChecker();
    }
}