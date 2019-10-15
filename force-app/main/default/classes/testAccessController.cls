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
           	
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
        	
	    	ESAPI.accessController().getCreatableFields(c);
	    	ESAPI.accessController().getUpdateableFields(c);
	    	ESAPI.accessController().getViewableFields(c);

	    	ESAPI.accessController().getCreatableFields(Contact.getSObjectType());
	    	ESAPI.accessController().getUpdateableFields(Contact.getSObjectType());
	    	ESAPI.accessController().getViewableFields(Contact.getSObjectType());
        	
        	c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().updateAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITHOUT);
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
        	c.LastName = 'ESAPI Test2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	ESAPI.accessController().updateAsUser(c, new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(c);
        	
        	c = new Contact();
        	c.LastName = 'ESAPI Test3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.INHERIT);
        	c = (Contact)ESAPI.accessController().insertAsUser(c, new List<String>{'LastName'});
        	
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
    
    static testMethod void testReturnedObjects() {
     	/* test return object and id with strings */
    	Contact tmp;
    	Contact tmp2;
    	Contact tmp3;
    	Contact tmp4;
        Contact c1 = new Contact();
        c1.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1'; // We add this long random to make sure we will not conflict with any real last name 
    	tmp = (Contact)ESAPI.accessController().insertAsUser(c1, new List<String>{'LastName'});
    	tmp2 = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1' limit 1];
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];
        	
    	System.assert(tmp != null, 'insertAsUser returned null');
    	System.assert(tmp2 != null, 'select with LastName after insertAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after insertAsUser returned null');
        	
    	System.assert(tmp.id == tmp2.id, 'select with LastName after insertAsUser returned id which is not equal to id from returned object');
    	System.assert(tmp.id == tmp3.id, 'select with tmp.id after insertAsUser returned id which is not equal to id from returned object');
        	
    	tmp.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1 updated';
    	tmp4 = (Contact)ESAPI.accessController().updateAsUser(tmp, new List<String>{'LastName'});
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];

    	System.assert(tmp4 != null, 'updateAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after updateAsUser returned null');
        	
    	System.assert(tmp.id == tmp4.id, 'id from returned object after updateAsUser is not equal to id from original returned object from insertAsUser');
    	System.assert(tmp.id == tmp3.id, 'id from select with id from original reurned object after insertAsUser, is not equal to id from original returned object from insertAsUser');
        	
    	System.assert(tmp.LastName == tmp3.LastName, 'c1.LastName == tmp3.LastName');
    	System.assert(tmp.LastName == tmp4.LastName, 'c1.LastName == tmp4.LastName');

    	/* test return object and id with Schema.SObjectField */
        c1 = new Contact();
        c1.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1'; // We add this long random to make sure we will not conflict with any real last name 
    	tmp = (Contact)ESAPI.accessController().insertAsUser(c1, new List<Schema.SObjectField>{Contact.LastName});
    	tmp2 = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1' limit 1];
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];
        	
    	System.assert(tmp != null, 'insertAsUser returned null');
    	System.assert(tmp2 != null, 'select with LastName after insertAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after insertAsUser returned null');
        	
    	System.assert(tmp.id == tmp2.id, 'select with LastName after insertAsUser returned id which is not equal to id from returned object');
    	System.assert(tmp.id == tmp3.id, 'select with tmp.id after insertAsUser returned id which is not equal to id from returned object');
        	
    	tmp.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c1 updated';
    	tmp4 = (Contact)ESAPI.accessController().updateAsUser(tmp, new List<Schema.SObjectField>{Contact.LastName});
    	tmp3 = [select LastName, Id from Contact where Id =: tmp.Id limit 1];

    	System.assert(tmp4 != null, 'updateAsUser returned null');
    	System.assert(tmp3 != null, 'select with tmp.id after updateAsUser returned null');
        	
    	System.assert(tmp.id == tmp4.id, 'id from returned object after updateAsUser is not equal to id from original returned object from insertAsUser');
    	System.assert(tmp.id == tmp3.id, 'id from select with id from original reurned object after insertAsUser, is not equal to id from original returned object from insertAsUser');
        	
    	System.assert(tmp.LastName == tmp3.LastName, 'c1.LastName == tmp3.LastName');
    	System.assert(tmp.LastName == tmp4.LastName, 'c1.LastName == tmp4.LastName');
    }
    
    static testMethod void testAccessControlArray() {
        String errStr;
        
        try {
        	// test with sharing
	        Contact c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray1 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        Contact c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        Contact [] arr = new Contact[]{c1, c2};
	        Database.SaveResult [] results;
	        
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	results = ESAPI.accessController().insertAsUser(arr, new List<Schema.SObjectField>{Contact.LastName}).getResults();
        	
        	System.assert(results.size() == 2, 'Could not insert two objects into db #1');
        	System.assert(results[0].isSuccess() == true, 'Could not insert first object into db #1 [0] - ' + results[0].getErrors());
        	System.assert(results[0].isSuccess() == true, 'Could not insert first object into db #1 [1] - ' + results[0].getErrors());
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #1');
			
			arr[0].LastName = 'ESAPI TestArray1 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray2 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<Schema.SObjectField>{Contact.LastName});
        	ESAPI.accessController().deleteAsUser(arr);
        	
        	// test without sharing
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITHOUT);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #2');
			
			arr[0].LastName = 'ESAPI TestArray3 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray4 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(arr);

        	// test inherit sharing
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.BEST_EFFORT);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.INHERIT);
        	results = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'}).getResults();
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #3');
			
			arr[0].LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
        	
        	ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});
        	ESAPI.accessController().deleteAsUser(arr);
        	
        	// test results class
	        c1 = new Contact();
	        c1.LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        c2 = new Contact();
	        c2.LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3'; // We add this long random to make sure we will not conflict with any real last name
	        arr = new Contact[]{c1, c2};
        	
        	ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
        	ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
        	
        	SFDCAccessControlResults.InsertResults insertResults;
        	sObject [] insertedObjects;
        	
        	insertResults = ESAPI.accessController().insertAsUser(arr, new List<String>{'LastName'});
        	
        	System.assert(insertResults.wasSuccessful() == true, 'insertResults.wasSuccessful() == true');
        	
        	results = insertResults.getResults();
        	System.assert(results.size() == 2, 'results.size() == 2');
        	
        	insertedObjects = insertResults.getInsertedObjects();
        	System.assert(insertedObjects.size() == 2, 'insertedObjects.size() == 2');
        	System.assert(insertedObjects[0].Id == results[0].getId(), 'insertedObjects[0].Id == results[0].getId()');
        	System.assert(insertedObjects[1].Id == results[1].getId(), 'insertedObjects[1].Id == results[1].getId()');
        	
        	arr = [select LastName,id from Contact where Id=:results[0].getId() or Id=:results[1].getId()];

			System.assert(arr.size() == 2, 'Could not get two objects from db #3');
			
			arr[0].LastName = 'ESAPI TestArray5 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';
			arr[1].LastName = 'ESAPI TestArray6 Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 updated';

        	SFDCAccessControlResults.UpdateResults updateResults;
        	sObject [] updatedObjects;
        	
        	updateResults = ESAPI.accessController().updateAsUser(new Map<ID, Contact>(arr), new List<String>{'LastName'});

        	System.assert(updateResults.wasSuccessful() == true, 'updateResults.wasSuccessful() == true');
        	
        	results = updateResults.getResults();
        	System.assert(results.size() == 2, 'results.size() == 2');
        	
        	updatedObjects = updateResults.getUpdatedObjects();
        	System.assert(updatedObjects.size() == 2, 'updatedObjects.size() == 2');
        	System.assert(updatedObjects[0].Id == results[0].getId(), 'updatedObjects[0].Id == results[0].getId()');
        	System.assert(updatedObjects[1].Id == results[1].getId(), 'updatedObjects[1].Id == results[1].getId()');
        	
        	SFDCAccessControlResults.DeleteResults deleteResults;
        	deleteResults = ESAPI.accessController().deleteAsUser(arr);
        	
        	System.assert(deleteResults.wasSuccessful() == true, 'deleteResults.wasSuccessful() == true');
        	
        	Database.DeleteResult [] delResults = deleteResults.getResults();
        	System.assert(delResults.size() == 2, 'delResults.size() == 2');
        	
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
    }
    
    static testMethod void testAccessControlConstructor() {
        String errStr;
        
        try {
	        SFDCAccessController ac = new SFDCAccessController(SFDCAccessController.SharingMode.WITHOUT, SFDCAccessController.OperationMode.ALL_OR_NONE, SFDCAccessController.OperationMode.ALL_OR_NONE);
        } catch (SFDCAccessControlException e) {
        	errStr = 'Access control violation - Type: ' + e.getExceptionType() + ' Reason: '  
        		+ e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: '  
        		+ e.getExceptionField() + ' Text: ' + e.getText(); 
        }
    }
    
    static testMethod void testLimits() {
    	/* This test is to confirm the new functions we added (insertAsUser and updateAsUser) 
    	   that use Schema.SObjectField indded solve the fields limiters issue. (fields has a limit of 10 calls)
    	   Now that we removed this limit, we should be able to call these functions until we hit the next type of
    	   limiter, this is likely to be DML operations which are capped at 100. This is why we are testing up to 100 */
    	   
    	Integer max = 100;
    	
    	for (Integer i = 0; i < max; i++) {
    		Contact c = new Contact();
    		c.LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c limits'; // We add this long random to make sure we will not conflict with any real last name
    		ESAPI.accessController().insertAsUser(c, new List<Schema.SObjectField>{Contact.LastName});
    	}
    	
    	Contact [] arr = [select LastName, Id from Contact where LastName = 'ESAPI Test Spu8UY&thuCrUzAPa2ASTaC7rA$Ra3 c limits'];
    	
    	System.assert(arr.size() == max, 'testLimits');
    }
}