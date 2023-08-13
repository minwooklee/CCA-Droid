package com.ccadroid;

import com.ccadroid.inspect.ApkParser;
import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import com.ccadroid.model.SlicingCriterion;
import com.ccadroid.util.soot.Soot;

import java.io.File;
import java.util.ArrayList;

public class EngineMain {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("[*] ERROR : No file path to be analyzed was entered!");
            System.exit(1);
        }

        String apkPath = args[0];
        System.out.println("[*] Analyzing APK : " + apkPath);

        ApkParser apkParser = ApkParser.getInstance();
        apkParser.loadAPKFile(apkPath);
        apkParser.parseManifest();
        apkParser.setDexClassNames();
        String packageName = apkParser.getPackageName();
        if (packageName != null) {
            System.out.println("[*] Package name : " + packageName);
        }

        Soot.initialize(apkPath);
        Soot.loadDexClasses();

        CodeInspector codeInspector = CodeInspector.getInstance();
        codeInspector.buildCallGraph();

        if (args.length < 2) {
            System.out.println("[*] ERROR : No rule file dir was entered!");
            System.exit(1);
        }

        File ruleFileDir = new File(args[1]);
        if (!ruleFileDir.exists()) {
            System.out.println("[*] ERROR : No rule file dir is exist!");
            System.exit(1);
        }

        SlicingCriteriaGenerator slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(ruleFileDir);
        for (SlicingCriterion sc : slicingCriteria) {

        }
    }
}