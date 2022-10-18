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

import java.security.Provider.Service;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import sun.security.util.Debug;

public final class SecurityRestrictProperties {

    private static final Debug debug = Debug.getInstance("semerufips");

    private static SecurityRestrictProperties instance = null;

    private static String descName;
    private static String descNumber;
    private static String descPolicy;
    private static String descSunsetDate;

    // Security properties
    private static String jdkTlsDisabledNamedCurves;
    private static String jdkTlsDisabledAlgorithms;
    private static String jdkTlsDphemeralDHKeySize;
    private static String jdkTlsLegacyAlgorithms;
    private static String jdkCertpathDisabledAlgorithms;
    private static String jdkSecurityLegacyAlgorithm;
    private static String keyStoreType;
    private static String keyStore;

    // For Secure Random
    private static String jdkSecureRandomProvider;
    private static String jdkSecureRandomAlgorithm;

    // Provider with argument (provider name + optional argument)
    private static ArrayList<String> providers;
    // Provider without argument
    private static ArrayList<String> providersSN;
    // Constraints for each provider if there are
    private static Map<String, String[][]> providerConstraints;

    private static String userSecurityNum = "0";
    private static boolean userSecurityTrace = false;
    private static boolean userSecurityAudit = false;
    private static boolean userSecurityHelp = false;

    // The java.security properties
    private Properties securityProps;

    /**
     * 
     * @param num   the security restrict setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     */
    private SecurityRestrictProperties(String num, Properties props, boolean trace, boolean audit, boolean help) {

        userSecurityNum = num;
        userSecurityTrace = trace;
        userSecurityAudit = audit;
        userSecurityHelp = help;
        securityProps = props;
    }

    /**
     * Get instance of SecurityRestrictProperties
     * 
     * @param num   the security restrict setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     * @return the created SecurityRestrictProperties instance
     */
    public static SecurityRestrictProperties getInstance(String num, Properties props, boolean trace, boolean audit,
            boolean help) {
        if (instance == null) {
            instance = new SecurityRestrictProperties(num, props, trace, audit, help);
        }
        return instance;
    }

    /**
     * Get instance of SecurityRestrictProperties
     * 
     * @return the created SecurityRestrictProperties instance
     */
    public static SecurityRestrictProperties getInstance() {
        // Need a default setting ?
        if (instance == null) {
            throw new RuntimeException(
                    "Security restrict mode initialization error, call getInstance with variables first.");
        }
        return instance;
    }

    /**
     * Initialize the security restrict properties
     */
    public void init() {
        if (debug != null) {
            debug.println("Loading Java security restrict properties.");
        }

        if (securityProps == null) {
            throw new RuntimeException(
                    "Security restrict mode initialization error, call getInstance with variables first.");
        }

        try {

            // Print out the Help and Audit info
            if (userSecurityHelp) {
                printHelp();
                if ("0".equals(userSecurityNum)) {
                    if (debug != null) {
                        debug.println("Print out the help info and exit.");
                    }
                    System.exit(0);
                }
            }
            if (userSecurityAudit) {
                listAudit();
                if ("0".equals(userSecurityNum)) {
                    if (debug != null) {
                        debug.println("Print out the audit info and exit.");
                    }
                    System.exit(0);
                }
            }

            // Load the security restrict providers from java.security properties
            initSecurityRestrictProviders();
            // Load the security restrict properties from java.security properties
            initSecurityRestrictProperties();
            // Load the security restrict provider constraints from java.security properties
            initSecurityRestrictConstraints();

            // Print out the Trace info
            if (userSecurityTrace)
                listTrace();

            if (debug != null) {
                debug.println("Loaded Java security restrict properties.");
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load Java security restrict properties.");
            }
            e.printStackTrace();
        }
    }

    /**
     * Load security restrict provider
     */
    private void initSecurityRestrictProviders() {

        if (debug != null) {
            debug.println("Loading security restrict providers.");
        }

        providers = new ArrayList<String>();
        providersSN = new ArrayList<String>();

        int pNum = 1;
        while (notNullEmpty(
                securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".jce.provider." + pNum))) {

            String providerInfo = securityProps
                    .getProperty("SecurityRestrict" + userSecurityNum + ".jce.provider." + pNum);

            if (!areBracketsBalanced(providerInfo)) {
                new RuntimeException("Security restrict provider format is inccorect: " + providerInfo)
                        .printStackTrace();
                System.exit(1);
            }

            String providerName = (providerInfo.indexOf("[") < 0) ? providerInfo.trim()
                    : providerInfo.substring(0, providerInfo.indexOf("[")).trim();
            // Provider with argument (provider name + optional argument)
            providers.add(pNum - 1, providerName);

            if (providerName.indexOf(" ") > 0) {
                providerName = providerName.substring(0, providerName.indexOf(" "));
            }
            // Provider without argument
            providersSN.add(pNum - 1, providerName);

            if (debug != null) {
                debug.println("Loaded security restrict provider: " + providers.get(pNum - 1) + " with short name: "
                        + providersSN.get(pNum - 1));
            }
            pNum++;
        }

        if (providers.isEmpty()) {
            new RuntimeException("Security restrict mode provider list empty, "
                    + "or no such security restrict policy in java.security file.").printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Load Security Restrict properties
     */
    private void initSecurityRestrictProperties() {

        if (debug != null) {
            debug.println("Loading security restrict properties.");
        }

        descName = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".desc.name").trim();
        descNumber = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".desc.number").trim();
        descPolicy = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".desc.policy").trim();
        descSunsetDate = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".desc.sunsetDate").trim();

        jdkTlsDisabledNamedCurves = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".tls.disabledNamedCurves").trim();
        jdkTlsDisabledAlgorithms = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".tls.disabledAlgorithms").trim();
        jdkTlsDphemeralDHKeySize = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".tls.ephemeralDHKeySize").trim();
        jdkTlsLegacyAlgorithms = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".tls.legacyAlgorithms").trim();
        jdkCertpathDisabledAlgorithms = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".jce.certpath.disabledAlgorithms").trim();
        jdkSecurityLegacyAlgorithm = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".jce.legacyAlgorithms");
        keyStoreType = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".keystore.type").trim();
        keyStore = securityProps.getProperty("SecurityRestrict" + userSecurityNum + ".javax.net.ssl.keyStore").trim();

        jdkSecureRandomProvider = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".securerandom.provider").trim();
        jdkSecureRandomAlgorithm = securityProps
                .getProperty("SecurityRestrict" + userSecurityNum + ".securerandom.algorithm").trim();

        if (debug != null) {
            debug.println("Loaded Security Restrict properties.");
        }
    }

    /**
     * Load security constraints with type, algorithm, attributes
     * 
     * Example:
     * SecurityRestrict1.jce.provider.1 = SUN [{CertPathBuilder, PKIX, *}, {Policy,
     * JavaPolicy, *}, {CertPathValidator, *, *}]
     */
    private void initSecurityRestrictConstraints() {

        // Key is the Provider Name, Value is the Constraints
        providerConstraints = new HashMap<String, String[][]>();

        for (int pNum = 1; pNum <= providersSN.size(); pNum++) {

            String providerName = providersSN.get(pNum - 1);
            String providerInfo = securityProps
                    .getProperty("SecurityRestrict" + userSecurityNum + ".jce.provider." + pNum);

            if (debug != null) {
                debug.println("Loading constraints for security provider: " + providerName);
            }

            // Provider with constraints
            if (providerInfo.indexOf("[") > 0) {

                providerInfo = providerInfo.trim().replaceAll(" ", "");
                String[] inputArray = providerInfo.substring(providerInfo.indexOf("[") + 2, providerInfo.length() - 2)
                        .split("\\},\\{");

                // Column is type, algorithm and attributes
                String[][] constraints = new String[inputArray.length][3];

                int cNum = 0;
                for (String input : inputArray) {
                    String[] constraint = input.trim().split(",");

                    constraints[cNum][0] = notNullEmpty(constraint[0]) ? constraint[0].trim() : "*";
                    constraints[cNum][1] = notNullEmpty(constraint[1]) ? constraint[1].trim() : "*";
                    constraints[cNum][2] = notNullEmpty(constraint[2]) ? constraint[2].trim() : "*";

                    if (debug != null) {
                        debug.println("Loading constraints for provider " + providerName + " with constraints type: "
                                + constraints[cNum][0] + " algorithm: " + constraints[cNum][1] + " attributes: "
                                + constraints[cNum][2]);
                    }
                    cNum++;
                }
                providerConstraints.put(providerName, constraints);
                if (debug != null) {
                    debug.println("Loaded constraints for security provider: " + providerName);
                }
            }
        }
    }

    /**
     * Check if the Service is allowed in security restrict mode
     * 
     * @param s the Service to check
     * @return true if the Service is allowed
     */
    public boolean isConstraintsAllow(Service s) {

        boolean isRegister = true;

        String providerName = s.getProvider().getName();
        String type = s.getType();
        String algorithm = s.getAlgorithm();

        // Provider with argument, remove argument
        // e.g. SunPKCS11-NSS-FIPS, remove argument -NSS-FIPS
        if (providerName.indexOf("-") > 0) {
            providerName = providerName.substring(0, providerName.indexOf("-"));
        }

        String[][] constraints = providerConstraints.get(providerName);

        // Go into the security provider constraints check if there are
        if (constraints != null && constraints.length >= 0) {

            isRegister = false;
            for (int cNum = 0; cNum < constraints.length; cNum++) {

                boolean cTypePut = "*".equals(constraints[cNum][0]) ? true
                        : type.equals(constraints[cNum][0]);
                boolean cAlgorithmPut = "*".equals(constraints[cNum][1]) ? true
                        : algorithm.equals(constraints[cNum][1]);
                boolean cAttributePut = "*".equals(constraints[cNum][2]);

                if (cTypePut && cAlgorithmPut && cAttributePut) {
                    if (debug != null) {
                        debug.println("Security constraints check, service type " + type + " algorithm " + algorithm
                                + " is allowed in provider " + providerName);
                    }
                    isRegister = true;
                    return isRegister;
                }

                if (cTypePut && cAlgorithmPut) {
                    String[] cAttributes = constraints[cNum][2].split(":");
                    cAttributePut = true;

                    for (String cAttribute : cAttributes) {
                        String[] input = cAttribute.trim().split("=");
                        String name = input[0];
                        String value = input[1];
                        cAttributePut = ((s.getAttribute(name) != null)
                                && value.equalsIgnoreCase(s.getAttribute(name))) ? cAttributePut && true
                                        : cAttributePut && false;
                    }

                    if (cAttributePut) {
                        if (debug != null) {
                            debug.println(
                                    "Security constraints check, service type " + type + " algorithm " + algorithm
                                            + " attribute " + constraints[cNum][2] + " is allowed in provider "
                                            + providerName);
                        }
                        isRegister = true;
                        return isRegister;
                    }
                }
            }
            if (debug != null) {
                debug.println("Security constraints check, service type " + type + " algorithm " + algorithm
                        + " is NOT allowed in provider " + providerName);
            }
        }
        return isRegister;
    }

    /**
     * Check if the provider is allowed in security restrict mode
     * 
     * @param provider the provider to check
     * @return true if the provider is allowed
     */
    public boolean isProviderAllow(String providerClass) {

        boolean isAllow = false;

        if (providerClass.equal("SunPKCS11-NSS-FIPS") || providerClass.equal("SUN")) {
            System.out.println("SunPKCS11-NSS-FIPS or SUN Stack trace:");
            StackTraceElement[] elements = Thread.currentThread().getStackTrace();
            for (int i = 1; i < elements.length; i++) {
                StackTraceElement stack = elements[i];
                System.out.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                        + stack.getFileName() + ":" + stack.getLineNumber() + ")");
            }
        }

        // Remove the provider class package name if there is.
        String providerName = providerClass.indexOf(".") > 0
                ? providerClass.substring(providerClass.lastIndexOf(".") + 1, providerClass.length())
                : providerClass;

        // Check if the provider is in the security restrict provider list
        // If not, the provider won't be registered.
        if (providersSN.contains(providerName)) {
            if (debug != null) {
                debug.println("The provider " + providerName + " is allowed in the security restrict mode.");
            }
            isAllow = true;
            return isAllow;
        }

        if (debug != null) {
            debug.println("The provider " + providerName + " is not allowed in the security restrict mode.");

            System.out.println("Stack trace:");
            StackTraceElement[] elements = Thread.currentThread().getStackTrace();
            for (int i = 1; i < elements.length; i++) {
                StackTraceElement stack = elements[i];
                System.out.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                        + stack.getFileName() + ":" + stack.getLineNumber() + ")");
            }
        }
        return isAllow;
    }

    /**
     * List Audit info if userSecurityAudit is ture, default as false
     */
    protected void listAudit() {

        System.out.println(" ");
        System.out.println("Security Restrict Audit Info: ");
        System.out.println("================ ");

        int num = 1;
        while (notNullEmpty(securityProps.getProperty("SecurityRestrict" + num + ".desc.name"))) {
            System.out.println("SecurityRestrict" + num + ".desc.name: "
                    + securityProps.getProperty("SecurityRestrict" + num + ".desc.name"));
            System.out.println("SecurityRestrict" + num + ".desc.number: "
                    + securityProps.getProperty("SecurityRestrict" + num + ".desc.number"));
            System.out.println("SecurityRestrict" + num + ".desc.policy: "
                    + securityProps.getProperty("SecurityRestrict" + num + ".desc.policy"));
            System.out.println("SecurityRestrict" + num + ".desc.sunsetDate: "
                    + securityProps.getProperty("SecurityRestrict" + num + ".desc.sunsetDate"));
            System.out.println(" ");
            num++;
        }
    }

    /**
     * List Trace info if userSecurityTrace is true, default as false
     */
    protected void listTrace() {

        System.out.println(" ");
        System.out.println("Security Restrict Trace Info: ");
        System.out.println("================ ");
        System.out.println("SecurityRestrict" + userSecurityNum + ".desc.name: " + descName);
        System.out.println("SecurityRestrict" + userSecurityNum + ".desc.number: " + descNumber);
        System.out.println("SecurityRestrict" + userSecurityNum + ".desc.policy: " + descPolicy);
        System.out.println("SecurityRestrict" + userSecurityNum + ".desc.sunsetDate: " + descSunsetDate);
        System.out.println(" ");

        // List only restrictions
        System.out.println("SecurityRestrict" + userSecurityNum + ".tls.disabledNamedCurves: "
                + jdkTlsDisabledNamedCurves);
        System.out.println("SecurityRestrict" + userSecurityNum + ".tls.disabledAlgorithms: "
                + jdkTlsDisabledAlgorithms);
        System.out.println("SecurityRestrict" + userSecurityNum + ".tls.ephemeralDHKeySize: "
                + jdkTlsDphemeralDHKeySize);
        System.out.println("SecurityRestrict" + userSecurityNum + ".tls.legacyAlgorithms: "
                + jdkTlsLegacyAlgorithms);
        System.out.println("SecurityRestrict" + userSecurityNum + ".jce.certpath.disabledAlgorithms: "
                + jdkCertpathDisabledAlgorithms);
        System.out.println("SecurityRestrict" + userSecurityNum + ".jce.legacyAlgorithms: "
                + jdkSecurityLegacyAlgorithm);

        System.out.println("SecurityRestrict" + userSecurityNum + ".keystore.type: "
                + keyStoreType);
        System.out.println("SecurityRestrict" + userSecurityNum + ".javax.net.ssl.keyStore: "
                + keyStore);        
        System.out.println("SecurityRestrict" + userSecurityNum + ".securerandom.provider: "
                + jdkSecureRandomProvider);
        System.out.println("SecurityRestrict" + userSecurityNum + ".securerandom.algorithm: "
                + jdkSecureRandomAlgorithm);

        // List providers
        System.out.println(" ");
        for (int pNum = 1; pNum <= providers.size(); pNum++) {
            System.out.println("SecurityRestrict" + userSecurityNum + ".jce.provider." + pNum + ": "
                    + providers.get(pNum - 1));
        }

        System.out.println(" ");
    }

    /**
     * Print help info if userSecurityHelp is ture, default as false
     */
    protected void printHelp() {

        System.out.println(" ");
        System.out.println("Usage: ");
        System.out.println("====== ");

        System.out.println(
                "-Dsemeru.securityrestrict=<n> this flag will select the settings for the user " 
                + "specified security restrict policy.");
        System.out.println(
                "-Dsemeru.securityrestrict=audit will list the name and number of all configured " + 
                "security restrict policies. it will NOT cause the jvm to terminate after printing " + 
                "the security restrict policies.");
        System.out.println(
                "-Dsemeru.securityrestrict=trace will list all properties relevant to the security " + 
                "restrict mode, including the existing default properties and the security restrict " + 
                "restrictions.");
        System.out.println("-Dsemeru.securityrestrict=help print help message.");

        System.out.println("e.g. ");
        System.out.println("    -Dsemeru.securityrestrict=1,trace,audit,help ");
        System.out.println("    -Dsemeru.securityrestrict=help ");

        System.out.println(" ");
    }

    /**
     * Check if the input string is not null and empty
     * 
     * @param string the input string
     * @return true if the input string is not null and emtpy
     */
    protected boolean notNullEmpty(String string) {
        return (string == null || string.isEmpty() || string.trim().isEmpty()) ? false : true;
    }

    /**
     * Function to check if brackets are balanced
     * 
     * @param string Input string for checking
     * @return true if the brackets are balanced
     */
    protected boolean areBracketsBalanced(String string) {

        Deque<Character> stack = new ArrayDeque<Character>();

        for (int i = 0; i < string.length(); i++) {
            char x = string.charAt(i);

            if (x == '(' || x == '[' || x == '{') {
                stack.push(x);
                continue;
            }

            char check;
            switch (x) {
                case ')':
                    check = stack.pop();
                    if (check == '{' || check == '[')
                        return false;
                    break;

                case '}':
                    check = stack.pop();
                    if (check == '(' || check == '[')
                        return false;
                    break;

                case ']':
                    check = stack.pop();
                    if (check == '(' || check == '{')
                        return false;
                    break;
            }
        }
        // Check Empty Stack
        return (stack.isEmpty());
    }

    public String getDescName() {
        return descName;
    }

    public String getDescNumber() {
        return descNumber;
    }

    public String getDescPolicy() {
        return descPolicy;
    }

    public String getDescSunsetDate() {
        return descSunsetDate;
    }

    public String getJdkTlsDisabledNamedCurves() {
        return jdkTlsDisabledNamedCurves;
    }

    public String getJdkTlsDisabledAlgorithms() {
        return jdkTlsDisabledAlgorithms;
    }

    public String getJdkTlsDphemeralDHKeySize() {
        return jdkTlsDphemeralDHKeySize;
    }

    public String getJdkTlsLegacyAlgorithms() {
        return jdkTlsLegacyAlgorithms;
    }

    public String getJdkCertpathDisabledAlgorithms() {
        return jdkCertpathDisabledAlgorithms;
    }

    public String getJdkSecurityLegacyAlgorithm() {
        return jdkSecurityLegacyAlgorithm;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public ArrayList<String> getProviders() {
        return providers;
    }

    public String getJdkSecureRandomProvider() {
        return jdkSecureRandomProvider;
    }

    public String getJdkSecureRandomAlgorithm() {
        return jdkSecureRandomAlgorithm;
    }
}
