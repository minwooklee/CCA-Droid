package com.ccadroid.util;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

public class Configuration {
    private static Properties prop;

    public static void loadConfig() {
        try {
            ClassLoader classLoader = Configuration.class.getClassLoader();
            URL url = classLoader.getResource("config.properties");
            if (url == null) {
                throw new IOException();
            }

            FileInputStream fis = new FileInputStream(url.getFile());
            BufferedInputStream bis = new BufferedInputStream(fis);

            prop = new Properties();
            prop.load(bis);
        } catch (IOException e) {
            System.out.println("[*] ERROR: " + e.getMessage());
            System.exit(1);
        }
    }

    public static String getProperty(String key) {
        return prop.getProperty(key);
    }
}