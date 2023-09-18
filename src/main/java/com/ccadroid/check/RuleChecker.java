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

        Object conditions = rule.get(CONDITIONS);
        Set<Map.Entry<String, ArrayList<Document>>> entries = targetSlicesMap.entrySet();
        for (Map.Entry<String, ArrayList<Document>> e : entries) {
            ArrayList<Document> slices = e.getValue();
            HashMap<String, LinkedHashSet<String>> misusedLinesMap = findMisusedLines(conditions, slices);
            if (misusedLinesMap.isEmpty()) {
                continue;
            }

            String groupId = e.getKey();
            Document targetSlice = getTargetSlice(groupId);
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

    private HashMap<String, LinkedHashSet<String>> findMisusedLines(Object conditions, ArrayList<Document> slices) {
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
                    String unitStr = checkAlgorithms(content, obj);
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
                    String unitStr = checkConstant(content, obj);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(content, obj);
                    unitStrings.addAll(tempStrings);
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

                JSONObject obj1 = getObject(arr, TARGET_SCHEME_TYPES);
                if (obj1 != null) {
                    String unitStr = checkSchemeTypes(content, obj1);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                JSONObject obj2 = getObject(arr, TARGET_ALGORITHMS);
                if (obj2 != null) {
                    String unitStr = checkAlgorithms(content, obj2);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                JSONObject obj3 = getObject(arr, TARGET_SIGNATURES);
                if (obj3 != null) {
                    String unitStr = checkSignatures(content, obj3);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }
                }

                JSONObject obj4 = getObject(arr, TARGET_CONSTANT);
                if (obj4 != null) {
                    String unitStr = checkConstant(content, obj4);
                    if (unitStr != null) {
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(content, obj4);
                    unitStrings.addAll(tempStrings);
                }

                if (!unitStrings.isEmpty()) {
                    String callerName = getCallerName(d);
                    map.put(callerName, unitStrings);
                }
            }
        }

        return map;
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
                        if (tempSlice.size() >= 1) {
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

    private JSONObject getObject(JSONArray arr, String key) {
        int len = arr.length();
        for (int i = 0; i < len; i++) {
            JSONObject obj = arr.getJSONObject(i);
            if (obj.has(key)) {
                return obj;
            }
        }

        return null;
    }

    private String getCallerName(Document slice) {
        String callerName = slice.getString(CALLER_NAME);
        if (callerName == null) {
            String groupId = slice.getString(GROUP_ID);
            Document targetSlice = getTargetSlice(groupId);
            callerName = targetSlice != null ? targetSlice.getString(CALLER_NAME) : null;
        }

        return callerName;
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

    private String checkSchemeTypes(List<Document> slice, JSONObject obj) {
        JSONArray types = obj.getJSONArray(TARGET_SCHEME_TYPES);
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

    private String checkAlgorithms(List<Document> slice, JSONObject obj) {
        JSONArray arr = obj.getJSONArray(TARGET_ALGORITHMS);
        for (Document l : slice) {
            if (!l.containsKey(CONSTANTS)) {
                continue;
            }

            int size = arr.length();
            List<String> constants = l.getList(CONSTANTS, String.class);
            for (String c : constants) {
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

    private String checkSignatures(List<Document> slice, JSONObject obj) {
        JSONArray arr = obj.getJSONArray(TARGET_SIGNATURES);
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

    private String checkConstant(List<Document> content, JSONObject obj) {
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

    private LinkedHashSet<String> checkArray(List<Document> content, JSONObject obj) {
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

    private Document getTargetSlice(String nodeId) {
        String query = "{'" + NODE_ID + "': '" + nodeId + "'}, {'" + GROUP_ID + "': '" + nodeId + "'}";
        if (sliceDatabase.selectCount(query) == 0) {
            return null;
        }

        FindIterable<Document> result = sliceDatabase.selectAll(query);

        return result.first();
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
            if (constant.contains("hmac")) {
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

    private static class Holder {
        private static final RuleChecker instance = new RuleChecker();
    }
}