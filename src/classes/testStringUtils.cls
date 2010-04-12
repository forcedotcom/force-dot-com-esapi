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
 * This class contains unit tests for validating the behavior of Apex classes
 * and triggers.
 *
 * Unit tests are class methods that verify whether a particular piece
 * of code is working properly. Unit test methods take no arguments,
 * commit no data to the database, and are flagged with the testMethod
 * keyword in the method definition.
 *
 * All test methods in an organization are executed whenever Apex code is deployed
 * to a production organization to confirm correctness, ensure code
 * coverage, and prevent regressions. All Apex classes are
 * required to have at least 75% code coverage in order to be deployed
 * to a production organization. In addition, all triggers must have some code coverage.
 * 
 * The @isTest class annotation indicates this class only contains test
 * methods. Classes defined with the @isTest annotation do not count against
 * the organization size limit for all Apex scripts.
 *
 * See the Apex Language Reference for more information about Testing and Code Coverage.
 */
@isTest
private class testStringUtils {

    static testMethod void testStringUtils1() {
    	String a = 'abc';
    	String b = ' ';
    	
   		System.assert(SFDCStringUtils.isEmpty(a) == false, 'Should be true - SFDCStringUtils.isEmpty(a)');
   		System.assert(SFDCStringUtils.notNullOrEmpty(a, false) == true, 'Should be true - SFDCStringUtils.notNullOrEmpty(a, false)');
   		System.assert(SFDCStringUtils.notNullOrEmpty(b, true) == false, 'Should be false - SFDCStringUtils.notNullOrEmpty(b, true)');
   		
   		String[] digit_arr = new String[]{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
   		Set<Integer> digits = SFDCStringUtils.stringArrayToIntegerSet(digit_arr);
   		System.assert(digits.size() == 10, 'Should be 10 - digits.size()');
   		System.assert(digits.contains(48) == true, 'Should be true - digits.contains(48)');
   		
   		String[] arr1 = new String[]{ '0', '1'};
   		String[] arr2 = new String[]{ '2', '3'};
   		
   		String[] arr3 = SFDCStringUtils.unionStringArrays(arr1, arr2);
   		System.assert(arr3.size() == 4, 'Should be 4 - arr3.size()');
    }
}