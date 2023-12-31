package com.ccadroid.check;

import com.ccadroid.slice.SliceDatabase;
import com.ccadroid.util.soot.SootUnit;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Sorts;
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
    }

    public void checkRules() {
        FindIterable<Document> result = sliceDatabase.selectAll("{'" + NODE_ID + "': {$exists: false}, '" + GROUP_ID + "': {$exists: true}}");
        HashMap<JSONObject, HashMap<String, ArrayList<Document>>> sliceMap = classifySlices(result);
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

            String groupId = e.getKey();
            Document targetSlice = getTargetSlice("{'" + NODE_ID + "': '" + groupId + "'}, {'" + GROUP_ID + "': '" + groupId + "'}");
            if (targetSlice == null) {
                continue;
            }

            String ruleId = rule.getString(RULE_ID);
            String description = rule.getString(DESCRIPTION);
            String callerName = targetSlice.getString(CALLER_NAME);
            String targetSignature = targetSlice.getString(TARGET_SIGNATURE);

            printResult(ruleId, description, callerName, targetSignature, misusedLinesMap);
        }
    }

    private HashMap<JSONObject, HashMap<String, ArrayList<Document>>> classifySlices(FindIterable<Document> result) {
        HashMap<JSONObject, HashMap<String, ArrayList<Document>>> slicesMap = new HashMap<>();

        for (Document s : result) {
            String groupId = s.getString(GROUP_ID);
            String targetSignature = s.getString(TARGET_SIGNATURE);
            List<String> targetParamNums = s.getList(TARGET_PARAM_NUMS, String.class);
            String targetParamNumStr = targetParamNums.toString();

            for (JSONObject r : rules) {
                HashMap<String, ArrayList<Document>> map = slicesMap.containsKey(r) ? slicesMap.get(r) : new HashMap<>();
                ArrayList<Document> targetSlices = new ArrayList<>();
                HashSet<Document> tempSlice = new HashSet<>();

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

                    FindIterable<Document> slices = sliceDatabase.selectAll("{'" + GROUP_ID + "': '" + groupId + "'}");
                    slices.sort(Sorts.descending("_id"));
                    for (Document d : slices) {
                        List<Document> content = d.getList(CONTENT, Document.class);
                        if (tempSlice.containsAll(content)) {
                            continue;
                        }

                        tempSlice.retainAll(content);
                        if (!tempSlice.isEmpty()) {
                            continue;
                        }

                        tempSlice.addAll(content);
                        targetSlices.add(d);
                    }

                    map.put(groupId, targetSlices);
                }

                slicesMap.put(r, map);
            }
        }

        return slicesMap;
    }

    private HashMap<String, LinkedHashSet<String>> findMisusedLines(Object conditions, Object targetAlgorithms, Object targetSignatures, ArrayList<Document> slices) {
        HashMap<String, LinkedHashSet<String>> map = new HashMap<>();

        if (conditions instanceof JSONObject) {
            JSONObject obj = (JSONObject) conditions;

            for (Document d : slices) {
                List<Document> content = d.getList(CONTENT, Document.class);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                if (obj.has(TARGET_SCHEME_TYPES)) {
                    String unitStr = checkSchemeTypes(content, obj);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_ALGORITHMS)) {
                    String unitStr = checkAlgorithms(content, obj, targetAlgorithms);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_SIGNATURES)) {
                    String unitStr = checkSignatures(content, obj);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_CONSTANT)) {
                    String unitStr = checkConstant(content, obj, targetSignatures);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(content, obj, targetSignatures);
                    if (tempStrings != null) {
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (!unitStrings.isEmpty()) {
                    String callerName = getCallerName(d);
                    map.put(callerName, unitStrings);
                }
            }

            removeUnsatisfiedItems(obj, map);
        } else {
            JSONArray arr = (JSONArray) conditions;

            for (Document d : slices) {
                List<Document> content = d.getList(CONTENT, Document.class);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                Object obj1 = getValue(arr, TARGET_SCHEME_TYPES);
                if (obj1 != null) {
                    String unitStr = checkSchemeTypes(content, obj1);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                Object obj2 = getValue(arr, TARGET_ALGORITHMS);
                if (obj2 != null) {
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
                    String unitStr = checkConstant(content, obj4, targetSignatures);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(content, obj4, targetSignatures);
                    if (tempStrings != null) {
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (!unitStrings.isEmpty()) {
                    String callerName = getCallerName(d);
                    map.put(callerName, unitStrings);
                }
            }
        }

        return map;
    }

    private Document getTargetSlice(String query) {
        return (sliceDatabase.selectCount(query) == 0) ? null : sliceDatabase.selectAll(query).first();
    }

    private void printResult(String ruleId, String description, String callerName, String targetSignature, HashMap<String, LinkedHashSet<String>> misusedLinesMap) {
        System.out.println();
        System.out.println("=======================================");
        System.out.println("[*] Rule ID: " + ruleId);
        System.out.println("[*] Description: " + description);
        System.out.println("[*] Caller name: " + callerName);
        System.out.println("[*] Target signature: " + targetSignature);
        System.out.println("[*] Target lines:");
        misusedLinesMap.forEach((key, value) -> {
            System.out.println(key + ":");
            for (String s : value) {
                System.out.println(s);
            }
        });
        System.out.println("=======================================");
    }

    private String getCallerName(Document slice) {
        String callerName = slice.getString(CALLER_NAME);
        if (callerName == null) {
            String groupId = slice.getString(GROUP_ID);
            Document targetSlice = getTargetSlice("{'" + NODE_ID + "': '" + groupId + "'}, {'" + GROUP_ID + "': '" + groupId + "'}");
            callerName = targetSlice != null ? targetSlice.getString(CALLER_NAME) : null;
        }

        return callerName;
    }

    private String checkSchemeTypes(List<Document> slice, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray types = ((JSONObject) object).getJSONArray(TARGET_SCHEME_TYPES);
        List<Object> typeAsList = types.toList();

        int sliceLen = slice.size();
        ArrayList<String> targetParamNums = new ArrayList<>();
        HashSet<String> targetVariables = new HashSet<>();

        for (int i = sliceLen - 1; i > -1; i--) {
            Document line = slice.get(i);
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
                if ((targetVariables.contains(targetVariable) && typeAsList.contains(ENCRYPT_THEN_MAC)) || (!targetVariables.contains(targetVariable) && typeAsList.contains(ENCRYPT_AND_MAC))) {
                    return unitStr;
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
                    return unitStr;
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

        return null;
    }

    private String checkAlgorithms(List<Document> slice, Object object, Object targetAlgorithms) {
        String oldUnitStr = checkAlgorithms(slice, object);
        if (targetAlgorithms == null) {
            return oldUnitStr;
        }

        String newUnitStr = checkAlgorithms(slice, targetAlgorithms);

        return findLateUnitString(slice, oldUnitStr, newUnitStr);
    }

    private String checkAlgorithms(List<Document> slice, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_ALGORITHMS) : (JSONArray) object;

        for (Document l : slice) {
            if (!l.containsKey(CONSTANTS)) {
                continue;
            }

            int size = arr.length();
            List<String> constants = l.getList(CONSTANTS, String.class);
            for (String c : constants) {
                c = c.replace("\"", "");
                if (!isAlgorithm(c)) {
                    continue;
                }

                for (int i = 0; i < size; i++) {
                    String algorithm = arr.getString(i);
                    Pattern pattern;
                    if (algorithm.contains("-")) {
                        String[] strArr = algorithm.split("-");
                        pattern = Pattern.compile("(?i)^(" + strArr[0] + ")?(?!" + strArr[1] + ")?$");
                    } else {
                        pattern = Pattern.compile("(?i)^(" + algorithm + ")?(/.*)?$");
                    }

                    Matcher matcher = pattern.matcher(c);
                    if (matcher.matches()) {
                        return l.getString(UNIT_STRING);
                    }
                }
            }
        }

        return null;
    }

    private String findSecureUnitString(List<Document> slice, Object targetSignatures) {
        String targetUnitStr = checkSignatures(slice, targetSignatures);
        if (targetUnitStr != null) {
            return targetUnitStr;
        }

        for (Document l : slice) {
            int unitType = l.getInteger(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitStr = l.getString(UNIT_STRING);
            String signature = getSignature(unitStr);
            String query = "{'" + CALLER_NAME + "': '" + signature + "'}";
            Document targetSlice = getTargetSlice(query);
            if (targetSlice == null) {
                continue;
            }

            List<Document> content = targetSlice.getList(CONTENT, Document.class);
            targetUnitStr = checkSignatures(content, targetSignatures);
            if (targetUnitStr == null) {
                continue;
            }

            targetUnitStr = unitStr;
            break;
        }

        return targetUnitStr;
    }

    private String checkSignatures(List<Document> slice, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_SIGNATURES) : (JSONArray) object;
        List<Object> arrAsList = arr.toList();

        for (Document l : slice) {
            int unitType = l.getInteger(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitStr = l.getString(UNIT_STRING);
            String signature = SootUnit.getSignature(unitStr);
            if (arrAsList.contains(signature)) {
                return unitStr;
            }
        }

        return null;
    }

    private String checkConstant(List<Document> slice, Object object, Object targetSignatures) {
        String oldUnitStr = checkConstant(slice, object);
        if (targetSignatures == null) {
            return oldUnitStr;
        }

        String newUnitStr = findSecureUnitString(slice, targetSignatures);

        return findLateUnitString(slice, oldUnitStr, newUnitStr);
    }

    private String findLateUnitString(List<Document> slice, String unitStr1, String unitStr2) {
        Document line1 = findLine(slice, unitStr1);
        Document line2 = findLine(slice, unitStr2);
        if (line1 == null || line2 == null) {
            return unitStr1;
        }

        return line1.getString(CALLER_NAME).equals(line2.getString(CALLER_NAME)) && line1.getInteger(LINE_NUMBER) < line2.getInteger(LINE_NUMBER) ? null : unitStr1;
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
                if (c.endsWith("f") || c.endsWith("F")) {
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
                    if (rsaKey != null) {
                        BigInteger modulus = rsaKey.getModulus();
                        c = String.valueOf(modulus);
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

    private LinkedHashSet<String> checkArray(List<Document> slice, Object object, Object targetSignatures) {
        LinkedHashSet<String> oldUnitStrings = checkArray(slice, object);
        if (oldUnitStrings.isEmpty() || targetSignatures == null) {
            return oldUnitStrings;
        }

        String oldUnitStr = new ArrayList<>(oldUnitStrings).get(0);
        String newUnitStr = findSecureUnitString(slice, targetSignatures);
        LinkedHashSet<String> newUnitStrings = new LinkedHashSet<>();
        if (newUnitStr != null) {
            newUnitStrings.add(newUnitStr);
        }

        return findLateUnitString(slice, oldUnitStr, newUnitStr) == null ? null : newUnitStrings;
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
            for (Document d : content) {
                String unitStr = d.getString(UNIT_STRING);
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
                    if (value != null) {
                        return value;
                    }
                }
            }
        } else if (object instanceof JSONArray) {
            JSONArray array = (JSONArray) object;
            for (Object o : array) {
                Object value = getValue(o, key);
                if (value != null) {
                    return value;
                }
            }
        }

        return null;
    }

    private Document findLine(List<Document> slice, String targetUnitStr) {
        if (targetUnitStr == null) {
            return null;
        }

        for (Document l : slice) {
            String unitStr = l.getString(UNIT_STRING);
            if (unitStr.contains(targetUnitStr)) {
                return l;
            }
        }

        return null;
    }

    private void removeUnsatisfiedItems(JSONObject obj, HashMap<String, LinkedHashSet<String>> map) {
        int count = obj.length();
        if (obj.has(TARGET_CONSTANT_SIZE)) {
            count--;
        }

        if (obj.has(TARGET_CONSTANT_LENGTH)) {
            count--;
        }

        HashMap<String, LinkedHashSet<String>> tempMap = new HashMap<>(map);
        Set<Map.Entry<String, LinkedHashSet<String>>> entries = tempMap.entrySet();
        for (Map.Entry<String, LinkedHashSet<String>> e : entries) {
            String callerName = e.getKey();
            LinkedHashSet<String> unitStrings = e.getValue();
            if ((entries.size() == 1 && count > unitStrings.size()) || (entries.size() > 1 && count > entries.size())) {
                map.remove(callerName);
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

    private boolean isAlgorithm(String constant) {
        constant = constant.toLowerCase();

        try {
            if (!constant.contains("hmac")) {
                Cipher.getInstance(constant);
            } else {
                Mac.getInstance(constant);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ignored) {
            return false;
        }

        return true;
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