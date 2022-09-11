/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

package openj9.internal.security;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import sun.security.util.Debug;

/**
 * Configures the security providers when in security restrict mode.
 */
public final class SecurityRestrictConfigurator {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Security restrict mode enable check, only supported on Linux x64.
    private static final boolean userEnabledSecurity;
    private static final boolean isSecuritySupported;
    private static final boolean shouldEnableSecurity;
    private static final String userSecuritySetting;
    private static final boolean userEnabledFIPS;

    private static String userSecurityNum = "0";
    private static boolean userSecurityTrace = false;
    private static boolean userSecurityAudit = false;
    private static boolean userSecurityHelp = false;

    private static final String[] supportPlatforms = {"amd64"};

    static {
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<>() {
                    @Override
                    public String[] run() {
                        return new String[] { System.getProperty("semeru.fips"),
                                System.getProperty("semeru.securityrestrict"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch") };
                    }
                });
        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        // If semeru.fips is true, then ignore semeru.securityrestrict, use userSecurityNum 1
        userSecuritySetting = userEnabledFIPS ? "1" : props[1];
        userEnabledSecurity = notNullEmpty(userSecuritySetting) ? true : false;
        isSecuritySupported = "Linux".equalsIgnoreCase(props[2])
                && Arrays.asList(supportPlatforms).contains(props[3]);
        shouldEnableSecurity = (userEnabledFIPS || userEnabledSecurity) && isSecuritySupported;
    }

    private SecurityRestrictConfigurator() {
        super();
    }

    /**
     * Security restrict mode will be enabled only if the semeru.fips system
     * property is true (default as false).
     *
     * @return true if Security restrict is enabled
     */
    public static boolean enableSecurityRestrict() {
        return shouldEnableSecurity;
    }

    /**
     * Remove the security providers and only add the security restrict providers.
     *
     * @param props the java.security properties
     * @return true if the security restrict properties loaded successfully
     */
    public static boolean configureSecurityRestrict(Properties props) {
        boolean loadedProps = false;

        // Check if security restrict is supported on this platform.
        if ((userEnabledFIPS || userEnabledSecurity) && !isSecuritySupported) {
            new RuntimeException("Security restrict mode is not supported on this platform.")
                    .printStackTrace();
            System.exit(1);
        }

        try {
            if (shouldEnableSecurity) {
                if (debug != null) {
                    debug.println("Security restrict mode detected, loading properties.");
                }

                // Read and set user security restrict settings
                initUserSecuritySetting();

                // Initialize the security restrict properties from java.security file
                SecurityRestrictProperties restricts = SecurityRestrictProperties.getInstance(userSecurityNum, 
                        props, userSecurityTrace, userSecurityAudit, userSecurityHelp);
                restricts.init();

                // Check if the SunsetDate expired
                if (isPolicySunset(restricts.getDescSunsetDate())) {
                    new RuntimeException("Security restrict policy expired.").printStackTrace();
                    System.exit(1);
                }

                // Check secure random settings
                if (!notNullEmpty(restricts.getJdkSecureRandomProvider())
                        || !notNullEmpty(restricts.getJdkSecureRandomAlgorithm())) {
                    new RuntimeException("Security restrict mode secure random is null.")
                            .printStackTrace();
                    System.exit(1);
                }

                // Remove all security providers.
                Iterator<Entry<Object, Object>> i = props.entrySet().iterator();
                while (i.hasNext()) {
                    Entry<Object, Object> e = i.next();
                    if (((String) e.getKey()).startsWith("security.provider")) {
                        if (debug != null) {
                            debug.println("Removing provider: " + e);
                        }
                        i.remove();
                    }
                }

                // Add security restrict providers.
                setSecurityRestrictProviders(props, restricts.getProviders());

                // Add security restrict Properties.
                setSecurityRestrictProperties(props, restricts);

                if (debug != null) {
                    debug.println("Security restrict mode loaded.");
                    debug.println("Security restrict properties: " + props.toString());
                }

                loadedProps = true;
            }

        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load security restrict mode configuration");
            }
            e.printStackTrace();
        }
        return loadedProps;
    }

    /**
     * Load user security restrict settings from system property
     */
    private static void initUserSecuritySetting() {

        if (debug != null) {
            debug.println("Load user security restrict settings.");
        }

        String[] inputs = userSecuritySetting.split(",");

        // For input ",,"
        if (inputs.length == 0) {
            new RuntimeException("user security restrict setting " + userSecuritySetting + " incorrect.")
                            .printStackTrace();
                    System.exit(1);
        }

        for (String input : inputs) {
            if (input.trim().equalsIgnoreCase("trace")) {
                userSecurityTrace = true;
            } else if (input.trim().equalsIgnoreCase("audit")) {
                userSecurityAudit = true;
            } else if (input.trim().equalsIgnoreCase("help")) {
                userSecurityHelp = true;
            } else {
                try {
                    Integer.parseInt(input.trim());
                } catch (NumberFormatException e) {
                    new RuntimeException("user security restrict setting " + userSecuritySetting + " incorrect.")
                            .printStackTrace();
                    System.exit(1);
                }
                userSecurityNum = input.trim();
            }
        }

        if (debug != null) {
            debug.println("User security restrict settings loaded, with userSecurityNum: " + userSecurityNum
                    + " userSecurityTrace: " + userSecurityTrace + " userSecurityAudit: " + userSecurityAudit
                    + " userSecurityHelp: " + userSecurityHelp);
        }
    }

    /**
     * Add security restrict providers
     * 
     * @param providers the provider name array
     */
    private static void setSecurityRestrictProviders(Properties props, ArrayList<String> providers) {

        if (debug != null) {
            debug.println("Adding security restrict provider.");
        }

        int pNum = 1;
        for (String provider : providers) {
            props.setProperty("security.provider." + pNum, provider);
            pNum ++;
            if (debug != null) {
                debug.println("Added security restrict provider: " + provider);
            }
        }
    }

    /**
     * Add security restrict properties
     * 
     * @param props the java.security properties
     */
    private static void setSecurityRestrictProperties(Properties props, SecurityRestrictProperties properties) {

        if (debug != null) {
            debug.println("Add security restrict properties.");
        }

        Map<String, String> propsMapping = new HashMap<>();

        // JDK properties name as Key, security restrict properties vaule as value
        propsMapping.put("jdk.tls.disabledNamedCurves", properties.getJdkTlsDisabledNamedCurves());
        propsMapping.put("jdk.tls.disabledAlgorithms", properties.getJdkTlsDisabledAlgorithms());
        propsMapping.put("jdk.tls.ephemeralDHKeySize", properties.getJdkTlsDphemeralDHKeySize());
        propsMapping.put("jdk.tls.legacyAlgorithms", properties.getJdkTlsLegacyAlgorithms());
        propsMapping.put("jdk.certpath.disabledAlgorithms", properties.getJdkCertpathDisabledAlgorithms());
        propsMapping.put("jdk.security.legacyAlgorithm", properties.getJdkSecurityLegacyAlgorithm());

        for (Map.Entry<String, String> entry : propsMapping.entrySet()) {
            String jdkPropsName = entry.getKey();
            String propsNewValue = entry.getValue();

            String propsOldValue = notNullEmpty(props.getProperty(jdkPropsName)) ? props.getProperty(jdkPropsName) : "";

            if (notNullEmpty(propsNewValue)) {
                props.setProperty(jdkPropsName,
                        notNullEmpty(propsOldValue) ? propsOldValue + ", " + propsNewValue : propsNewValue);
                if (debug != null) {
                    debug.println("Add security restrict properties, with property: " + jdkPropsName + " values: "
                            + (notNullEmpty(propsOldValue) ? propsOldValue + ", " + propsNewValue : propsNewValue));
                }
            }
        }

        // For keyStore and keystore.type, old value not needed, just set the new value
        if (notNullEmpty(properties.getKeyStoreType()))
            props.setProperty("keystore.type", properties.getKeyStoreType());
        if (notNullEmpty(properties.getKeyStore()))
            System.setProperty("javax.net.ssl.keyStore", properties.getKeyStore());
    }

    /**
     * Check if security restrict policy sunset
     * 
     * @param descSunsetDate the sun set date from java.security
     * @return true if the security restrict policy sunset
     */
    private static boolean isPolicySunset(String descSunsetDate) {

        boolean isSunset = false;
        try {
            if (LocalDate.parse(descSunsetDate, DateTimeFormatter.ofPattern("MM/dd/yyyy")).isBefore(LocalDate.now())) {
                isSunset = true;
            }
        } catch (Exception except) {
            new RuntimeException(
                    "Security restrict policy sunset date is inccorect, the correct format is MM/dd/yyyy.")
                    .printStackTrace();
            System.exit(1);
        }

        if (debug != null) {
            debug.println("Security restrict policy is sunset: " + isSunset);
        }

        return isSunset;
    }

    /**
     * Check if the input string is not null and empty
     * 
     * @param string the input string
     * @return true if the input string is not null and emtpy
     */
    protected static boolean notNullEmpty(String string) {
        return (string == null || string.isEmpty() || string.trim().isEmpty()) ? false : true;
    }
}
