package com.ccadroid.check;

import com.ccadroid.slice.SliceDatabase;
import com.ccadroid.util.soot.SootUnit;
import com.mongodb.client.FindIterable;
import org.bson.Document;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.mariuszgromada.math.mxparser.Argument;
import org.mariuszgromada.math.mxparser.Expression;
import org.mariuszgromada.math.mxparser.License;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ccadroid.check.RuleConstants.*;
import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class RuleChecker {
    private static final Pattern BASE64_PATTERN = Pattern.compile("^([A-Za-z\\d+/]{4})*([A-Za-z\\d+/]{3}=|[A-Za-z\\d+/]{2}==)?$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[\\da-fA-F]+$");
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
                System.out.println("[*] ERROR: Cannot import rule file: " + f.getName());
            }
        }

        rules.sort((o1, o2) -> {
            JSONObject rule1 = o1.getJSONObject(INSECURE_RULE);
            JSONObject rule2 = o2.getJSONObject(INSECURE_RULE);
            String ruleNum1 = rule1.getString(RULE_ID).split("-")[0];
            String ruleNum2 = rule2.getString(RULE_ID).split("-")[0];

            return Integer.compare(Integer.parseInt(ruleNum1), Integer.parseInt(ruleNum2));
        });
    }

    public void extractLines(List<Document> content, String targetVariable, String targetSignature, String targetParamNum, List<Document> targetLines) {
        ArrayList<Document> tempContent = new ArrayList<>(content);
        Collections.reverse(tempContent);

        Document lastLine = tempContent.get(0);
        if (!targetLines.contains(lastLine)) {
            targetLines.add(lastLine);
        }

        for (Document l : tempContent) {
            if (l.equals(lastLine)) {
                continue;
            }

            String unitStr = l.getString(UNIT_STRING);
            if (targetVariable != null && !unitStr.contains(targetVariable)) {
                continue;
            }

            if (targetSignature != null && targetSignature.equals(l.getString(CALLER_NAME))) {
                continue;
            }

            if (targetLines.contains(l)) {
                continue;
            }

            targetLines.add(0, l);
            int unitType = l.getInteger(UNIT_TYPE);
            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                ArrayList<String> paramValues = getParamValues(unitStr);

                if ((className.equals("java.util.Arrays") && methodName.equals("copyOf")) || (className.equals("java.lang.System") && methodName.equals("arraycopy"))) {
                    targetVariable = paramValues.get(0);
                } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                    targetVariable = paramValues.get(1);
                } else if (className.contains("java.util.Base64$Decoder") && methodName.equals("decode")) {
                    targetVariable = paramValues.get(0);
                } else if (className.equals("javax.crypto.spec.PBEKeySpec") && methodName.equals("<init>")) { // for SecretKeyFactory.generateSecret()
                    targetVariable = paramValues.get(0);
                } else {
                    if (targetSignature != null && unitStr.contains(targetSignature)) {
                        targetVariable = paramValues.get(Integer.parseInt(targetParamNum));
                        targetSignature = null;
                        targetParamNum = null;
                    } else {
                        if (targetVariable != null && !unitStr.startsWith(targetVariable)) {
                            continue;
                        }

                        String valueStr = getLocalValue(unitStr);
                        if (valueStr == null) {
                            continue;
                        }

                        extractLines(content, valueStr, null, null, targetLines);
                    }
                }
            } else if (unitType == PARAMETER) {
                String paramNum = getParamNumber(unitStr, unitType);
                extractLines(content, null, l.getString(CALLER_NAME), paramNum, targetLines);
            } else if (unitType == NEW_INSTANCE) {
                break;
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                break;
            } else if (unitType == CAST) {
                targetVariable = getRightInternalValue(unitStr, unitType);
            }
        }
    }

    public void checkRules() {
        HashMap<JSONObject, HashMap<String, ArrayList<Document>>> sliceMap = classifySlices();
        if (sliceMap.isEmpty()) {
            return;
        }

        Set<Map.Entry<JSONObject, HashMap<String, ArrayList<Document>>>> entries = sliceMap.entrySet();
        for (Map.Entry<JSONObject, HashMap<String, ArrayList<Document>>> e : entries) {
            JSONObject root = e.getKey();
            HashMap<String, ArrayList<Document>> targetSlicesMap = e.getValue();

            checkRules(root, targetSlicesMap, INSECURE_RULE);
            checkRules(root, targetSlicesMap, SECURE_RULE);
        }
    }

    private HashMap<JSONObject, HashMap<String, ArrayList<Document>>> classifySlices() {
        LinkedHashMap<JSONObject, HashMap<String, ArrayList<Document>>> slicesMap = new LinkedHashMap<>();

        String query1 = "{'" + CALLER_NAME + "': {$exists: false}}";
        FindIterable<Document> result1 = sliceDatabase.selectAll(query1);
        for (Document s1 : result1) {
            String nodeId = s1.getString(NODE_ID);
            String targetStatement = s1.getString(TARGET_STATEMENT);
            List<String> targetParamNumbers = s1.getList(TARGET_PARAM_NUMBERS, String.class);
            String targetParamNumStr = targetParamNumbers.toString();

            for (JSONObject o : rules) {
                HashMap<String, ArrayList<Document>> map = slicesMap.containsKey(o) ? slicesMap.get(o) : new HashMap<>();
                ArrayList<Document> targetSlices = new ArrayList<>();
                HashSet<Document> tempContent = new HashSet<>();

                JSONObject obj = o.getJSONObject(SLICING_SIGNATURES);
                Map<String, Object> objAsMap = obj.toMap();
                Set<Map.Entry<String, Object>> entries = objAsMap.entrySet();
                for (Map.Entry<String, Object> e : entries) {
                    String signature = e.getKey();
                    Object paramNumbers = e.getValue();
                    if (!targetStatement.equals(signature)) {
                        continue;
                    }

                    String paramNumStr = paramNumbers.toString();
                    if (!(targetParamNumStr.equals(paramNumStr))) {
                        continue;
                    }

                    ArrayList<Document> result2 = getRelatedSlices(nodeId);
                    for (Document s2 : result2) {
                        List<Document> content = s2.getList(CONTENT, Document.class);
                        if (tempContent.containsAll(content)) {
                            continue;
                        }

                        tempContent.retainAll(content);
                        if (!tempContent.isEmpty()) {
                            continue;
                        }

                        tempContent.addAll(content);
                        targetSlices.add(s2);
                    }

                    map.put(nodeId, targetSlices);
                }

                slicesMap.put(o, map);
            }
        }

        return slicesMap;
    }

    private ArrayList<Document> getRelatedSlices(String nodeId) {
        ArrayList<Document> slices = new ArrayList<>();
        String query2 = "{'" + NODE_ID + "': '" + nodeId + "', '" + CALLER_NAME + "': {$exists: false}}";
        FindIterable<Document> mergedSlices = sliceDatabase.selectAll(query2);
        for (Document s : mergedSlices) {
            slices.add(s);
        }

        ArrayList<String> queue = new ArrayList<>();
        queue.add(nodeId);

        while (!queue.isEmpty()) {
            String id = queue.remove(0);
            String query = "{'" + NODE_ID + "': '" + id + "', '" + CALLER_NAME + "': {$exists: true}}";
            Document slice = sliceDatabase.findSlice(query);
            if (slice == null) {
                continue;
            }

            if (slices.contains(slice)) {
                continue;
            } else if (!id.equals(nodeId) && !slices.contains(slice)) {
                slices.add(slice);
            }

            List<String> relatedNodeIds = slice.getList(RELATED_NODE_IDS, String.class);
            if (relatedNodeIds.isEmpty()) {
                break;
            }

            queue.addAll(relatedNodeIds);
        }

        return slices;
    }

    private HashMap<String, LinkedHashSet<String>> findMisusedLines(Object conditions, Object targetAlgorithms, Object targetSignatures, ArrayList<Document> slices) {
        HashMap<String, LinkedHashSet<String>> map = new HashMap<>();
        HashMap<String, String> targetSignatureMap = getTargetSignatureMap(slices);

        if (conditions instanceof JSONObject) {
            JSONObject obj = (JSONObject) conditions;
            int hasSchemeType = 0;
            int hasAlgorithm = 0;
            int hasSignature = 0;
            int hasConstant = 0;

            for (Document s : slices) {
                String callerName = getCallerName(s);
                boolean hasCipherAndMac = hasCipherAndMac(callerName);
                List<Document> content = s.getList(CONTENT, Document.class);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                if (((obj.has(TARGET_SCHEME_TYPES) && !targetSignatureMap.isEmpty()) || obj.has(REQUIRED_SCHEME_TYPES)) && hasSchemeType == 0) {
                    String unitStr = checkSchemeTypes(s, content, obj, targetSignatureMap);
                    if (unitStr != null) {
                        hasSchemeType = 1;
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_ALGORITHMS) && !hasCipherAndMac) {
                    String unitStr = checkAlgorithms(content, obj, targetAlgorithms);
                    if (unitStr != null) {
                        hasAlgorithm = 1;
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_SIGNATURES)) {
                    String unitStr = checkSignatures(content, obj);
                    if (unitStr != null) {
                        hasSignature = 1;
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_CONSTANT)) {
                    String unitStr = checkConstant(s, content, obj, targetSignatures);
                    if (unitStr != null) {
                        hasConstant = 1;
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(s, content, obj, targetSignatures);
                    if (tempStrings != null && !tempStrings.isEmpty()) {
                        hasConstant = 1;
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (unitStrings.isEmpty()) {
                    continue;
                }

                LinkedHashSet<String> targetStrings = map.containsKey(callerName) ? map.get(callerName) : new LinkedHashSet<>();
                targetStrings.addAll(unitStrings);
                map.put(callerName, targetStrings);
            }

            int count = hasSchemeType + hasAlgorithm + hasSignature + hasConstant;
            int targetCount = getTargetCount(obj);
            if (count != targetCount) {
                map.clear();
            }
        } else {
            JSONArray arr = (JSONArray) conditions;

            for (Document s : slices) {
                String callerName = getCallerName(s);
                boolean hasCipherAndMac = hasCipherAndMac(callerName);
                List<Document> content = s.getList(CONTENT, Document.class);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                Object obj1 = getValue(arr, TARGET_SCHEME_TYPES);
                if (obj1 != null) {
                    if (!targetSignatureMap.isEmpty()) {
                        String unitStr = checkSchemeTypes(s, content, obj1, targetSignatureMap);
                        if (unitStr != null) {
                            unitStrings.add(unitStr);
                        }
                    }
                }

                Object obj2 = getValue(arr, TARGET_ALGORITHMS);
                if (obj2 != null && !hasCipherAndMac) {
                    String unitStr = checkAlgorithms(content, obj2, targetAlgorithms);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                Object obj3 = getValue(arr, TARGET_SIGNATURES);
                if (obj3 != null) {
                    String unitStr = checkSignatures(content, obj3);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                Object obj4 = getValue(arr, TARGET_CONSTANT);
                if (obj4 != null) {
                    String unitStr = checkConstant(s, content, obj4, targetSignatures);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(s, content, obj4, targetSignatures);
                    if (tempStrings != null) {
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (unitStrings.isEmpty()) {
                    continue;
                }

                LinkedHashSet<String> targetStrings = map.containsKey(callerName) ? map.get(callerName) : new LinkedHashSet<>();
                targetStrings.addAll(unitStrings);
                map.put(callerName, targetStrings);
            }
        }

        return map;
    }

    private void checkRules(JSONObject root, HashMap<String, ArrayList<Document>> targetSlicesMap, String ruleName) {
        if (!root.has(ruleName)) {
            return;
        }

        JSONObject rule = root.getJSONObject(ruleName);
        if (!rule.has(CONDITIONS)) {
            return;
        }

        Object targetAlgorithms = null;
        Object targetSignatures = null;
        if (ruleName.equals(INSECURE_RULE)) {
            JSONObject secureRule = root.getJSONObject(SECURE_RULE);
            targetAlgorithms = getValue(secureRule, TARGET_ALGORITHMS);
            targetSignatures = getValue(secureRule, TARGET_SIGNATURES);
        }

        Object conditions = rule.get(CONDITIONS);
        Set<Map.Entry<String, ArrayList<Document>>> entries = targetSlicesMap.entrySet();
        for (Map.Entry<String, ArrayList<Document>> e : entries) {
            ArrayList<Document> slices = e.getValue();
            HashMap<String, LinkedHashSet<String>> misusedLinesMap = findMisusedLines(conditions, targetAlgorithms, targetSignatures, slices);
            if (misusedLinesMap.isEmpty()) {
                continue;
            }

            String nodeId = e.getKey();
            String query = "{'" + NODE_ID + "': '" + nodeId + "', '" + CALLER_NAME + "': {$exists: true}}";
            Document targetSlice = sliceDatabase.findSlice(query);
            if (targetSlice == null) {
                continue;
            }

            String ruleId = rule.getString(RULE_ID);
            String description = rule.getString(DESCRIPTION);
            String callerName = targetSlice.getString(CALLER_NAME);
            String targetStatement = targetSlice.getString(TARGET_STATEMENT);

            printResult(ruleId, description, callerName, targetStatement, misusedLinesMap);
        }
    }

    private String checkSchemeTypes(Document slice, List<Document> content, Object object, HashMap<String, String> targetSignatureMap) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (object instanceof JSONObject) ? (JSONObject) object : new JSONObject();
        if (obj.has(REQUIRED_SCHEME_TYPES)) {
            return findTargetString(slice);
        }

        JSONArray types = (object instanceof JSONObject) ? obj.getJSONArray(TARGET_SCHEME_TYPES) : (JSONArray) object;
        List<Object> typeAsList = types.toList();

        String targetVariable = null;
        String targetParamNumber = null;
        String targetSignature = null;

        for (int i = content.size() - 1; i > -1; i--) {
            Document line = content.get(i);
            String unitStr = line.getString(UNIT_STRING);
            int unitType = line.getInteger(UNIT_TYPE);
            if (targetVariable != null && unitStr.startsWith(targetVariable) && unitType == PARAMETER) {
                targetParamNumber = getParamNumber(unitStr, unitType);
                targetSignature = line.getString(CALLER_NAME);
                continue;
            }

            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String signature = getSignature(unitStr);
            String className = getClassName(signature);
            String methodName = getMethodName(signature);
            ArrayList<String> paramValues = getParamValues(unitStr);
            if (className.equals("javax.crypto.Cipher") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                if (targetVariable == null && paramValues.isEmpty()) { // for doFinal()
                    continue;
                } else if (targetVariable == null && paramValues.size() == 1) { // update or doFinal(byte[])
                    targetVariable = paramValues.get(0);
                    continue;
                }

                if (targetVariable != null && ((unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_THEN_MAC)) || (!unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_AND_MAC)))) {
                    String query2 = "{$set: {'" + TARGET_STRING + "': '" + unitStr + "'}}";
                    sliceDatabase.update(slice, query2);

                    return unitStr;
                }
            } else if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                if (!paramValues.contains(targetVariable)) {
                    continue;
                }

                targetVariable = paramValues.get(0);
            } else if (className.equals("javax.crypto.Mac") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                if (targetVariable == null && paramValues.isEmpty()) { // for doFinal()
                    continue;
                } else if (targetVariable == null && paramValues.size() == 1) { // update or doFinal(byte[])
                    targetVariable = paramValues.get(0);
                    continue;
                }

                if (targetVariable != null && unitStr.startsWith(targetVariable) && typeAsList.contains(MAC_THEN_ENCRYPT)) {
                    String query2 = "{$set: {'" + TARGET_STRING + "': '" + unitStr + "'}}";
                    sliceDatabase.update(slice, query2);

                    return unitStr;
                }
            } else if (targetParamNumber != null && targetSignature != null && unitStr.contains(targetSignature)) {
                int index = Integer.parseInt(targetParamNumber);
                targetVariable = paramValues.get(index);

                targetParamNumber = null;
                targetSignature = null;
            } else if (targetVariable != null && targetSignatureMap.containsValue(signature)) {
                if ((unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_THEN_MAC)) || (!unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_AND_MAC))) {
                    String query2 = "{$set: {'" + TARGET_STRING + "': '" + unitStr + "'}}";
                    sliceDatabase.update(slice, query2);

                    return unitStr;
                }
            }
        }

        return null;
    }

    private String checkAlgorithms(List<Document> content, Object object, Object targetAlgorithms) {
        String oldUnitStr = checkAlgorithms(content, object);
        if (targetAlgorithms == null) {
            return oldUnitStr;
        }

        String newUnitStr = checkAlgorithms(content, targetAlgorithms);

        return findLateUnitString(content, oldUnitStr, newUnitStr);
    }

    private String checkAlgorithms(List<Document> content, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_ALGORITHMS) : (JSONArray) object;
        int arrSize = arr.length();

        for (Document l : content) {
            List<String> constants = l.getList(CONSTANTS, String.class);
            if (constants == null) {
                continue;
            }

            for (String c : constants) {
                c = c.replace("\"", "");
                if (!isAlgorithm(c)) {
                    continue;
                }

                for (int i = 0; i < arrSize; i++) {
                    boolean flag;
                    String algorithm = arr.getString(i);
                    String regex = "-";

                    if (algorithm.contains(regex)) {
                        String[] strArr = algorithm.split(regex);
                        Pattern pattern = Pattern.compile("(?i)^(" + strArr[0] + ")?(/.*)?$");
                        Matcher matcher = pattern.matcher(c);
                        flag = matcher.matches() && !c.toLowerCase().contains(strArr[1]);
                    } else {
                        Pattern pattern = Pattern.compile("(?i)^(" + algorithm + ")?(/.*)?$");
                        Matcher matcher = pattern.matcher(c);
                        flag = matcher.matches();
                    }

                    if (flag) {
                        return l.getString(UNIT_STRING);
                    }
                }
            }
        }

        return null;
    }

    private String checkSignatures(List<Document> content, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_SIGNATURES) : (JSONArray) object;
        List<Object> objects = arr.toList();

        List<Document> tempContent = new ArrayList<>(content);
        Collections.reverse(tempContent);

        for (Document l : tempContent) {
            int unitType = l.getInteger(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitStr = l.getString(UNIT_STRING);
            String signature = SootUnit.getSignature(unitStr);
            if (objects.contains(signature)) {
                return unitStr;
            }
        }

        return null;
    }

    private String checkConstant(Document slice, List<Document> content, Object object, Object targetSignatures) {
        List<Document> targetLines = new ArrayList<>();

        List<String> targetParamNumbers = slice.getList(TARGET_PARAM_NUMBERS, String.class);
        List<String> targetVariables = slice.getList(TARGET_VARIABLES, String.class);
        String targetVariable;
        if (targetParamNumbers == null) {
            targetVariable = targetVariables.get(0);
        } else if (targetParamNumbers.contains("-1") && targetVariables.size() == 2) {
            targetVariable = targetVariables.get(1);
        } else {
            targetVariable = targetVariables.get(0);
        }

        extractLines(content, targetVariable, null, null, targetLines);
        if (targetLines.isEmpty()) {
            return null;
        }

        String oldUnitStr = checkConstant(targetLines, object);
        if (targetSignatures == null) {
            return oldUnitStr;
        }

        String newUnitStr = findSecureUnitString(content, targetSignatures);

        return findLateUnitString(content, oldUnitStr, newUnitStr);
    }

    private String checkConstant(List<Document> content, Object object) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (JSONObject) object;
        String regex = obj.getString(TARGET_CONSTANT);
        Pattern targetPattern = Pattern.compile(regex);
        String length = obj.has(TARGET_CONSTANT_LENGTH) ? obj.getString(TARGET_CONSTANT_LENGTH) : null;
        String size = obj.has(TARGET_CONSTANT_SIZE) ? obj.getString(TARGET_CONSTANT_SIZE) : null;

        for (Document l : content) {
            if (!l.containsKey(CONSTANTS)) {
                continue;
            }

            List<String> constants = l.getList(CONSTANTS, String.class);
            for (String c : constants) {
                c = c.replace("\"", "");
                if (c.contains(".") && (c.endsWith("f") || c.endsWith("F"))) {
                    c = String.valueOf((int) Double.parseDouble(c));
                }

                Matcher matcher = targetPattern.matcher(c);
                if (!matcher.matches()) {
                    continue;
                }

                if (isAlgorithm(c)) {
                    continue;
                }

                if (regex.equals(".*") && size == null && isNumber(c)) {
                    continue;
                }

                if (length != null) {
                    c = String.valueOf(c.length());
                }

                if (size != null) {
                    RSAKey rsaKey = convertToRSAKey(c);
                    if (rsaKey == null) {
                        c = (isNumber(c)) ? c : String.valueOf(c.length());
                    } else {
                        BigInteger modulus = rsaKey.getModulus();
                        int bitLength = modulus.bitLength();
                        c = String.valueOf(bitLength);
                    }
                }

                if (length != null || size != null) {
                    Argument argument = new Argument("x=" + c);
                    String expression = (length == null) ? size : length;
                    Expression e = new Expression(expression, argument);
                    if (e.calculate() == 0) {
                        continue;
                    }
                }

                return l.getString(UNIT_STRING);
            }
        }

        return null;
    }

    private LinkedHashSet<String> checkArray(Document slice, List<Document> content, Object object, Object targetSignatures) {
        List<Document> targetLines = new ArrayList<>();

        List<String> targetParamNumbers = slice.getList(TARGET_PARAM_NUMBERS, String.class);
        List<String> targetVariables = slice.getList(TARGET_VARIABLES, String.class);
        String targetVariable;
        if (targetParamNumbers == null) {
            targetVariable = targetVariables.get(0);
        } else if (targetParamNumbers.contains("-1") && targetVariables.size() == 2) {
            targetVariable = targetVariables.get(1);
        } else {
            targetVariable = targetVariables.get(0);
        }

        extractLines(content, targetVariable, null, null, targetLines);
        if (targetLines.isEmpty()) {
            return null;
        }

        LinkedHashSet<String> oldUnitStrings = checkArray(targetLines, object);
        if (oldUnitStrings.isEmpty()) {
            return oldUnitStrings;
        }

        if (targetSignatures == null) {
            return oldUnitStrings;
        }

        String newUnitStr = findSecureUnitString(content, targetSignatures);
        if (newUnitStr == null) {
            return oldUnitStrings;
        }

        String oldUnitStr = new ArrayList<>(oldUnitStrings).get(0);
        LinkedHashSet<String> newUnitStrings = new LinkedHashSet<>();
        newUnitStrings.add(newUnitStr);

        return findLateUnitString(content, oldUnitStr, newUnitStr) == null ? null : newUnitStrings;
    }

    private LinkedHashSet<String> checkArray(List<Document> content, Object object) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (JSONObject) object;
        LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

        Document firstLine = content.get(0);
        int firstUnitType = firstLine.getInteger(UNIT_TYPE);
        if (firstUnitType != NEW_ARRAY) {
            return unitStrings;
        }

        Document secondLine = content.get(1);
        int secondUnitType = secondLine.getInteger(UNIT_TYPE);
        Document lastLine = content.get(content.size() - 1);
        int lastUnitType = lastLine.getInteger(UNIT_TYPE);

        String expression = obj.has(TARGET_CONSTANT_LENGTH) ? obj.getString(TARGET_CONSTANT_LENGTH) : null;
        if (expression != null) {
            String unitStr = firstLine.getString(UNIT_STRING);
            String arraySize = getArraySize(unitStr, firstUnitType);
            Argument argument = new Argument("x=" + arraySize);
            Expression e = new Expression(expression, argument);
            if (e.calculate() == 0) {
                return unitStrings;
            }
        }

        if (secondUnitType == ASSIGN_ARRAY_CONSTANT && lastUnitType == ASSIGN_SIGNATURE_VARIABLE) {
            for (Document l : content) {
                String unitStr = l.getString(UNIT_STRING);
                unitStrings.add(unitStr);
            }
        } else {
            String unitStr = firstLine.getString(UNIT_STRING);
            unitStrings.add(unitStr);
        }

        return unitStrings;
    }

    private Object getValue(Object object, String key) {
        if (object instanceof JSONObject) {
            JSONObject obj = (JSONObject) object;
            if (obj.has(key)) {
                return obj.get(key);
            } else {
                Set<String> keys = obj.keySet();
                for (String k : keys) {
                    Object value = getValue(obj.get(k), key);
                    if (value == null) {
                        continue;
                    }

                    return value;
                }
            }
        } else if (object instanceof JSONArray) {
            JSONArray array = (JSONArray) object;
            for (Object o : array) {
                Object value = getValue(o, key);
                if (value == null) {
                    continue;
                }

                return value;
            }
        }

        return null;
    }

    private HashMap<String, String> getTargetSignatureMap(ArrayList<Document> slices) {
        boolean isCipher = false;
        boolean isMac = false;
        HashMap<String, String> targetSignatureMap = new HashMap<>();

        for (Document s : slices) {
            String callerName = getCallerName(s);
            List<Document> content = s.getList(CONTENT, Document.class);
            for (Document l : content) {
                int unitType = l.getInteger(UNIT_TYPE);
                if ((unitType & INVOKE) != INVOKE) {
                    continue;
                }

                String unitStr = l.getString(UNIT_STRING);
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("javax.crypto.Cipher") && (methodName.equals("update") || methodName.equals("doFinal"))) {
                    isCipher = true;
                    targetSignatureMap.put(className, callerName);
                } else if (className.equals("javax.crypto.Mac") && (methodName.equals("update") || methodName.equals("doFinal"))) {
                    isMac = true;
                    targetSignatureMap.put(className, callerName);
                }
            }

            if (isCipher && isMac) {
                break;
            }
        }

        return (isCipher && isMac) ? targetSignatureMap : new HashMap<>();
    }

    private boolean hasCipherAndMac(String callerName) {
        String query1 = "{'" + "callerName" + "': '" + callerName + "', 'content.unitString': {'$regex': 'javax.crypto.Cipher'}}";
        String query2 = "{'" + "callerName" + "': '" + callerName + "', 'content.unitString': {'$regex': 'javax.crypto.Mac'}}";
        Document cipherResult = sliceDatabase.findSlice(query1);
        Document macResult = sliceDatabase.findSlice(query2);

        return cipherResult != null && macResult != null;
    }

    private String getCallerName(Document slice) {
        String callerName = slice.getString(CALLER_NAME);
        if (callerName == null) {
            String nodeId = slice.getString(NODE_ID);
            String query = "{'" + NODE_ID + "': '" + nodeId + "', '" + CALLER_NAME + "': {$exists: true}}";
            Document targetSlice = sliceDatabase.findSlice(query);
            callerName = targetSlice == null ? null : targetSlice.getString(CALLER_NAME);
        }

        return callerName;
    }

    private String findTargetString(Document slice) {
        String callerName = getCallerName(slice);
        String className = getClassName(callerName);

        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.Mac: byte[] doFinal()>");
        targetSignatures.add("<javax.crypto.Mac: byte[] doFinal(byte[])>");
        targetSignatures.add("<javax.crypto.Mac: void doFinal(byte[],int)>");

        for (String s : targetSignatures) {
            String query1 = "{" + CALLER_NAME + ": {$regex: '" + className + "'}, " + TARGET_STATEMENT + ": '" + s + "'}";
            Document targetSlice1 = sliceDatabase.findSlice(query1);
            if (targetSlice1 == null) {
                continue;
            }

            String nodeId = targetSlice1.getString(NODE_ID);
            String query2 = "{" + NODE_ID + ": '" + nodeId + "', " + TARGET_STRING + ": {$exists : true}}";
            Document targetSlice2 = sliceDatabase.findSlice(query2);
            if (targetSlice2 == null) {
                continue;
            }

            return targetSlice2.getString(TARGET_STRING);
        }

        return null;
    }

    private int getTargetCount(JSONObject obj) {
        int count = 0;
        if (obj.has(TARGET_SCHEME_TYPES) || obj.has(REQUIRED_SCHEME_TYPES)) {
            count++;
        }

        if (obj.has(TARGET_ALGORITHMS)) {
            count++;
        }

        if (obj.has(TARGET_SIGNATURES)) {
            count++;
        }

        if (obj.has(TARGET_CONSTANT)) {
            count++;
        }

        return count;
    }

    private void printResult(String ruleId, String description, String callerName, String targetStatement, HashMap<String, LinkedHashSet<String>> misusedLinesMap) {
        System.out.println();
        System.out.println("=======================================");
        System.out.println("[*] Rule ID: " + ruleId);
        System.out.println("[*] Description: " + description);
        System.out.println("[*] Caller name: " + callerName);
        System.out.println("[*] Target statement: " + targetStatement);
        System.out.println("[*] Target lines:");
        misusedLinesMap.forEach((key, value) -> {
            System.out.println(key + ":");
            for (String s : value) {
                System.out.println(s);
            }
        });
        System.out.println("=======================================");
    }

    private String findLateUnitString(List<Document> content, String unitStr1, String unitStr2) {
        Document line1 = findLine(content, unitStr1);
        Document line2 = findLine(content, unitStr2);
        if (line1 == null || line2 == null) {
            return unitStr1;
        }

        return line1.getString(CALLER_NAME).equals(line2.getString(CALLER_NAME)) && line1.getInteger(LINE_NUMBER) <= line2.getInteger(LINE_NUMBER) ? null : unitStr1;
    }

    private Document findLine(List<Document> content, String targetUnitStr) {
        if (targetUnitStr == null) {
            return null;
        }

        for (Document l : content) {
            String unitStr = l.getString(UNIT_STRING);
            if (unitStr.contains(targetUnitStr)) {
                return l;
            }
        }

        return null;
    }

    private String findSecureUnitString(List<Document> content, Object targetSignatures) {
        String targetUnitStr = checkSignatures(content, targetSignatures);
        if (targetUnitStr != null) {
            return targetUnitStr;
        }

        for (Document l : content) {
            int unitType = l.getInteger(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitStr = l.getString(UNIT_STRING);
            String signature = getSignature(unitStr);
            String query = "{'" + CALLER_NAME + "': '" + signature + "'}";
            Document targetSlice = sliceDatabase.findSlice(query);
            if (targetSlice == null) {
                continue;
            }

            List<Document> targetContent = targetSlice.getList(CONTENT, Document.class);
            targetUnitStr = checkSignatures(targetContent, targetSignatures);
            if (targetUnitStr == null) {
                continue;
            }

            targetUnitStr = unitStr;
            break;
        }

        return targetUnitStr;
    }

    private boolean isAlgorithm(String constant) {
        constant = constant.toLowerCase();

        try {
            Cipher.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ignored) {

        }

        try {
            SecretKeyFactory.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            Mac.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        return false;
    }

    private boolean isNumber(String constant) {
        try {
            Integer.parseInt(constant);
        } catch (NumberFormatException ignored) {
            return false;
        }

        return true;
    }

    private RSAKey convertToRSAKey(String str) {
        String s = str.replace("\"", "");
        s = s.replace("\\r", "").replace("\\n", "");

        byte[] bytes = null;
        if (isBase64String(s)) {
            bytes = DatatypeConverter.parseBase64Binary(s);
        } else if (isHexString(s)) {
            if (s.length() % 2 == 1) {
                s = "0" + s;
            }

            bytes = DatatypeConverter.parseHexBinary(s);
        }

        return (bytes == null) ? null : getRSAKey(bytes);
    }

    private boolean isBase64String(String str) {
        Matcher matcher = BASE64_PATTERN.matcher(str);

        return matcher.matches();
    }

    private boolean isHexString(String str) {
        Matcher matcher = HEX_PATTERN.matcher(str);

        return matcher.matches();
    }

    private RSAKey getRSAKey(byte[] bytes) {
        RSAKey key = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            key = (RSAPublicKey) publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            key = (RSAPrivateKey) privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        return key;
    }

    private static class Holder {
        private static final RuleChecker instance = new RuleChecker();
    }
}