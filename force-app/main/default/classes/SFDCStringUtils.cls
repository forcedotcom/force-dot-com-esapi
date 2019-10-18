/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - Salesforce.com
 * 
 * The Apex ESAPI implementation is published by Salesforce.com under the New BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Yoel Gluck (securecloud .at. salesforce.com) <a href="http://www.salesforce.com">Salesforce.com</a>
 * @created 2010
 */

/**
 * A collection of utility methods to perform String analysis and transformations
 */
public with sharing class SFDCStringUtils {

	private SFDCStringUtils() {
		// prevent instantiation
	}

    /**
     * Check to ensure that a {@code String} is not null or empty (after optional
     * trimming of leading and trailing whitespace). 
     * 
     * @param str   The {@code String} to be checked.
     * @param trim  If {@code true}, the string is first trimmed before checking
     *              to see if it is empty, otherwise it is not.
     * @return      True if the string is null or empty (after possible
     *              trimming); otherwise false.
     */
    public static boolean notNullOrEmpty(String str, boolean trim) {
        if ( trim ) {
            return !( str == null || str.trim().equals('') );
        } else {
            return !( str == null || str.equals('') );
        }
    }
    
    /**
     * Returns true if String is empty ('') or null.
     */
    public static boolean isEmpty(String str) {
        return str == null || str.length() == 0;
    }
    
	/**
	 * Converts an array of Strings to a Set of Integers. 
	 * @param array the contents of the new Set
	 * @return a Set containing the elements in the array
	 */
	public static Set<Integer> stringArrayToIntegerSet(String[] arr) {
		Set<Integer> toReturn = new Set<Integer>();
		for (String c : arr) {
			toReturn.add(SFDCCharacter.toInt(c));
		}
		return toReturn;
	}
	
	public static String[] unionStringArrays(String[] a, String[] b) {
		
		Set<String> tmp = new Set<String>();
		String[] ret;
		Integer i;
		
		// add all unique strings
		tmp.addAll(a);
		tmp.addAll(b);
		
		List<String> tmpList = new List<String>();
		tmpList.addAll(tmp);
		tmpList.sort();
		
		// get all strings into an array of strings
		ret = new String[tmpList.size()];
		i = 0;
		for (String s : tmpList) {
			ret[i] = s;
			i++;
		}
		
		return ret;
	}
}