package com.ccadroid.util;

import com.ccadroid.inspect.ApkParser;
import soot.Scene;
import soot.options.Options;

import java.util.ArrayList;
import java.util.Collections;

public class Soot {

    public static void initialize(String apkPath) {
        String sdkHomeDir = System.getenv("ANDROID_SDK_HOME");
        if (sdkHomeDir == null) {
            System.err.println("Please set ANDROID_SDK_HOME environment variable!");
            System.exit(1);
        }

        Options.v().set_process_multiple_dex(true);
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(sdkHomeDir + "/" + "platforms");
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_full_resolver(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_ignore_resolving_levels(true);
    }

    public static void loadDexClasses() {
        ApkParser apkParser = ApkParser.getInstance();
        ArrayList<String> dexClassNames = apkParser.getDexClassNames();
        for (String s : dexClassNames) {
            try {
                Scene.v().loadClassAndSupport(s);
            } catch (NoClassDefFoundError | IllegalArgumentException ignored) {

            }
        }

        Scene.v().loadBasicClasses();
        Scene.v().loadNecessaryClasses();
    }

    private Soot() throws InstantiationException {
        throw new InstantiationException();
    }
}