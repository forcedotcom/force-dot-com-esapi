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
private class testAccessController {

    static testMethod void testAccessControl() {
        Contact c = new Contact();
        c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name 
        String errStr;
        
        try {
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c = [select LastName from Contact where LastName='ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3' limit 1];
        	
	    	ESAPI.accessController().getCreatableFields(c);
	    	ESAPI.accessController().getUpdateableFields(c);
	    	ESAPI.accessController().getViewableFields(c);
        	
        	c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITHOUT);
        	ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c = [select LastName from Contact where LastName='ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3' limit 1];
        	
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.INHERIT);
        	ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c = [select LastName from Contact where LastName='ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3' limit 1];
        	
        	c.LastName = 'ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
        
        SFDCAccessController ac = new SFDCAccessController(SFDCAccessController.SharingMode.WITHOUT, SFDCAccessController.OperationMode.ALL_OR_NONE);
        ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        
        try {
        	ESAPI.accessController().setOperationMode(null);
        	System.assert(false, 'Should never get here');
        } catch (Exception e) {
        	// should fail - so all good
        }
        
        try {
        	ESAPI.accessController().setSharingMode(null);
        	System.assert(false, 'Should never get here');
        } catch (Exception e) {
        	// should fail - so all good
        }
        
        try {
        	c = new Contact();
        	c.LastName = 'ESAPI Test4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	ESAPI.accessController().insertAsUser(c, new List<String>{'LastName123DOESNOTEXIST'});
        	
        	System.assert(false, 'Should never get here');
        } catch (SFDCAccessControlException e) {
        	// should fail - so all good
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
    }
}