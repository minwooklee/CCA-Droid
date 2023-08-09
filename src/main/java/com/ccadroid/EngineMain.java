package com.ccadroid;

import com.ccadroid.inspect.ApkParser;

public class EngineMain {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("[*] ERROR : No file path to be analyzed was entered!");
            System.exit(1);
        }

        String apkPath = args[0];
        ApkParser apkParser = new ApkParser(apkPath);
        System.out.println("[*] Analyzing APK : " + apkPath);
        String packageName = apkParser.getPackageName();
        if (packageName != null) {
            System.out.println("[*] Package name : " + packageName);
        }
    }
}