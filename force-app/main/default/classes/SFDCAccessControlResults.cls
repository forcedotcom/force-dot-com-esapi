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
 * This class provides access control results functionality.
 * This will help to encapsulate and provide more functionality in processing 
 * results from access control function calls such as insertAsUser and updateAsUser.
 */
global with sharing virtual class SFDCAccessControlResults {
	
	private Database.SaveResult [] saveResultsArr; // this object will hold the results for upadte and insert operations
	private Database.DeleteResult [] deleteResultsArr; // this object will hold the results for delete operations
	private SObject [] cleanObjectsArr; // this object will hold the actual objects used to insert/update into db
	
	global class AccessControlResultsException extends Exception {}
	
	private SFDCAccessControlResults() {
		// declare this function as private so it can't be used.
		// the specific Insert/Update/Delete classes should be constructed instead.
		
		saveResultsArr = null;
		deleteResultsArr = null;
		cleanObjectsArr = null;
	}
	
	/**
	 * This class provides results info and functionality for insert operations.
	 */
	global with sharing class InsertResults extends SFDCAccessControlResults {
		
		/**
		 * This constructor sets the objects that were actually inserted into the db, and also sets the results from that insert operation.
		 */
		global InsertResults(SObject [] objects, Database.SaveResult [] results) {
			super();
			setCleanObjectsArr(objects);
			setSaveResultsArr(results);
		}

		/**
		 * Get the Database.SaveResult [] returned by the insert operation.
		 */
		global Database.SaveResult [] getResults() {
			return saveResultsArr;
		}

		/**
		 * Get the objects that were actually inserted into the db.<br>
		 * Note that these objects might not be the same as the objects you provided to the insertAsUser function.<br>
		 * Depending on the current user permissions, the operation mode, and the fields you requested to set, this might<br>
		 * not be all the fields you have in your original objects. 
		 */
		global SObject [] getInsertedObjects() {
			return cleanObjectsArr;
		}

		/**
		 * Did the insert operation succeed for all objects in the array?<br>
		 * Note that if array operation mode was set to BEST_EFFORT, we will not get an exception even if some<br>
		 * of the objects fail to insert.
		 */
		global Boolean wasSuccessful() {
			return wasSaveSuccessful();
		}
	}

	/**
	 * This class provides results info and functionality for update operations.
	 */
	global with sharing class UpdateResults extends SFDCAccessControlResults {

		/**
		 * This constructor sets the objects that were actually used to update the db, and also sets the results from that update operation.
		 */
		global UpdateResults(SObject [] objects, Database.SaveResult [] results) {
			super();
			setCleanObjectsArr(objects);
			setSaveResultsArr(results);
		}

		/**
		 * Get the Database.SaveResult [] returned by the update operation.
		 */
		global Database.SaveResult [] getResults() {
			return saveResultsArr;
		}

		/**
		 * Get the objects that were actually updated into the db.<br>
		 * Note that these objects might not be the same as the objects you provided to the updateAsUser function.<br>
		 * Depending on the current user permissions, the operation mode, and the fields you requested to set, this might<br>
		 * not be all the fields you have in your original objects. 
		 */
		global SObject [] getUpdatedObjects() {
			return cleanObjectsArr;
		}

		/**
		 * Did the update operation succeed for all objects in the array?<br>
		 * Note that if array operation mode was set to BEST_EFFORT, we will not get an exception even if some<br>
		 * of the objects fail to update.
		 */
		global Boolean wasSuccessful() {
			return wasSaveSuccessful();
		}
	}

	/**
	 * This class provides results info and functionality for delete operations.
	 */
	global with sharing class DeleteResults extends SFDCAccessControlResults {

		/**
		 * This constructor sets the results from the delete operation.
		 */
		global DeleteResults(Database.DeleteResult [] results) {
			super();
			setDeleteResultsArr(results);
		}

		/**
		 * Get the Database.DeleteResult [] returned by the delete operation.
		 */
		global Database.DeleteResult [] getResults() {
			return deleteResultsArr;
		}
		
		/**
		 * Did the delete operation succeed for all objects in the array?<br>
		 * Note that if array operation mode was set to BEST_EFFORT, we will not get an exception even if some<br>
		 * of the objects fail to delete.
		 */
		global Boolean wasSuccessful() {
			return wasDeleteSuccessful();
		}
	}
	
	// main class private functions
	
	private void setCleanObjectsArr(SObject [] objects) {
		if (objects == null)
			throw new AccessControlResultsException('objects must not be set to null');
		cleanObjectsArr = objects;
	}

	private void setSaveResultsArr(Database.SaveResult [] results) {
		if (results == null)
			throw new AccessControlResultsException('results must not be set to null');
		saveResultsArr = results;
	}

	private void setDeleteResultsArr(Database.DeleteResult [] results) {
		if (results == null)
			throw new AccessControlResultsException('results must not be set to null');
		deleteResultsArr = results;
	}
	
	private Boolean wasSaveSuccessful() {
		if (saveResultsArr == null)
			throw new AccessControlResultsException('saveResultsArr must not be null');
		Integer i;
		for (i = 0; i < saveResultsArr.size(); i++) {
			if (saveResultsArr[i].isSuccess() == false)
				return false;
		} 
		return true;
	}	

	private Boolean wasDeleteSuccessful() {
		if (deleteResultsArr == null)
			throw new AccessControlResultsException('deleteResultsArr must not be null');
		Integer i;
		for (i = 0; i < deleteResultsArr.size(); i++) {
			if (deleteResultsArr[i].isSuccess() == false)
				return false;
		} 
		return true;
	}	
}