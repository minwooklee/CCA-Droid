package com.ccadroid;

import com.ccadroid.inspect.ApkParser;
import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.util.soot.Soot;

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
    }
}