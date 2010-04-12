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
private class testStringValidationRule {

    static testMethod void testStringValidationRule1() {
    	SFDCStringValidationRule svr = new SFDCStringValidationRule('test', '^[\\d]*$');
    	
    	svr.addBlacklistPattern('((.)*)[0]((.)*)');
    	svr.setMaximumLength(20);
    	svr.setMinimumLength(2);
    	svr.setAllowNull(false);
    	
    	svr.assertValid('567');
    	
    	svr = new SFDCStringValidationRule('test2');
    	
    	svr.addWhitelistPattern(pattern.compile('^[\\d]*$'));
    	svr.addBlacklistPattern(pattern.compile('((.)*)[0]((.)*)'));
    	svr.setMaximumLength(20);
    	svr.setMinimumLength(2);
    	svr.setAllowNull(true);
    	
    	svr.assertValid('567');
    	
    	try {
    		svr.assertValid('405'); // should fail because of the zero
    		System.assert(false, 'Should never get here - 405');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    	
    	try {
    		svr.assertValid('abc'); // should fail because not digits
    		System.assert(false, 'Should never get here - abc');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    	
    	try {
    		svr.assertValid('1'); // should fail because shorter than minimum
    		System.assert(false, 'Should never get here - 1');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}

    	try {
    		svr.assertValid('123456789123456789123456789'); // should fail because longer than maximum
    		System.assert(false, 'Should never get here - 123456789123456789123456789');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    	
    	svr.assertValid(null);
    	svr.assertValid('');
    	
    	svr.setAllowNull(false);
    	
    	try {
    		svr.assertValid(null); // should fail because null
    		System.assert(false, 'Should never get here - null');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    	
    	try {
    		String a = null;
    		svr.addWhitelistPattern(a);
    		System.assert(false, 'Should never get here');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    	
    	try {
    		String a = null;
    		svr.addBlacklistPattern(a);
    		System.assert(false, 'Should never get here');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}

    	try {
    		Pattern a = null;
    		svr.addWhitelistPattern(a);
    		System.assert(false, 'Should never get here');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}

    	try {
    		Pattern a = null;
    		svr.addBlacklistPattern(a);
    		System.assert(false, 'Should never get here');
    	} catch (SFDCValidator.SFDCValidationException e) {
    		// should fail - so all good
    	}
    }
}