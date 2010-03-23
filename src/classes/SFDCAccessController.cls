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
 * This class provides access control functionality to enforce CRUD/FLS and sharing in the force.com platform.
 */
global class SFDCAccessController {
	
	/*
		SharingMode - this enum defines the sharing mode to be used:
			WITH - will use the class instance that enforces "with sharing"
			WITHOUT -  will use the class instance that enforces "without sharing"
			INHERIT - will use the class instance that just inherits from the class that calls this class
		You can set the sharing mode in the constructor or later using the setSharingMode() method.
		If you use the default constructor, we will set it to WITH 
	*/
	global enum SharingMode {WITH, WITHOUT, INHERIT}

	/*
		OperationMode - this enum defines the DB operations mode to be used:
			ALL_OR_NONE - will make sure all required fields have the proper permissions before any operation takes place
			BEST_EFFORT - will only set fields that are allowed. Other fields will be omited from operation, but operation will continue.
		You can set the operation mode in the constructor or later using the setOperatoinMode() method.
		If you use the default constructor, we will set it to ALL_OR_NONE 
	*/
	global enum OperationMode {ALL_OR_NONE, BEST_EFFORT}
	
	global class AccessControlDmlException extends Exception {}
	
	/* Helper classes : we use these just to help enforce the sharing rules based on input parameters. Most
	 *  of the actual code is in the parent class AccessControllerInternal. From the SFDCAccessController.xxx 
	 *  function, we will call the corresponding function in one of these helper function classes instances.
	 *
	 * Example : When the developer calls SFDCAccessController.insertAsUser(sobj, fieldsToSet) and sobj being 
	 *  an sObject he wants our library to add with the proper permission checks. We will do this internally:
	 *    getACImpl().insertAsUser(sobj, fieldsToSet);
	 *  getACImpl() will return the correct helper class instance object based on the current sharing mode. So
	 *  if we are in "with sharing" mode (SharingMode.WITH), it will return the instance that was created using 
	 *  the helper class defined "with sharing". This way when we call getACImpl().insertAsUser() it will perform
	 *  the key operations (i.e. dbQuery, dbInsert, etc.) in that sharing mode because those key statements are 
	 *  executed in that class, and only other tests (CRUD/FLS) is executed in a common code base (AccessControllerInternal)
	 *  
	 * Note : because sharing is enforced based on code location, and not class definition of instance used, 
	 *  we most actually have the important code statements in these classes that are defined with the 
	 *  appropriate sharing rule.
	 */
	private with sharing class AccessControllerWithSharing extends AccessControllerInternal {
		private override List<SObject> dbQuery(String query) { return Database.query(query); }
		private override void dbInsert(sObject obj) { insert obj; }
		private override void dbUpdate(sObject obj) { update obj; }
		private override void dbDelete(sObject obj) { delete obj; }
	}
	
	private without sharing class AccessControllerWithoutSharing extends AccessControllerInternal {
		private override List<SObject> dbQuery(String query) { return Database.query(query); }
		private override void dbInsert(sObject obj) { insert obj; }
		private override void dbUpdate(sObject obj) { update obj; }
		private override void dbDelete(sObject obj) { delete obj; }
	}
	
	private class AccessControllerInheritSharing extends AccessControllerInternal{
		private override List<SObject> dbQuery(String query) { return Database.query(query); }
		private override void dbInsert(sObject obj) { insert obj; }
		private override void dbUpdate(sObject obj) { update obj; }
		private override void dbDelete(sObject obj) { delete obj; }
	}
	
	/* Helper interface : this interface will allow us to have a single interface defintion for all three sharing mode classes.
	 *  This type is returned by the helper function getACImpl() so that no matter what object type it is actually returning,
	 *  we can use it to call these same functions defined in the interface.
	 */
	private interface AccessControllerInterface {
		void insertAsUser(SObject someObj, List<String> fieldsToSet);
		void updateAsUser(SObject someObj, List<String> fieldsToUpdate);
		void deleteAsUser(SObject someObj);
		List<Schema.SObjectField> getViewableFields(SObject someObj);
		List<Schema.SObjectField> getUpdateableFields(SObject someObj);
		List<Schema.SObjectField> getCreatableFields(SObject someObj);
	}
	
	/* instance variables */
	private AccessControllerWithSharing acws; // sharing access control object that was created with sharing
	private AccessControllerWithoutSharing acwos; // sharing access control object that was created without sharing
	private AccessControllerInheritSharing acis; // sharing access control object that was created with sharing inherited from caller
	private SharingMode smode; // the current sharing mode of this instance. We will call the proper instance from the above three based on this value.
	
	/* default constructor - will set sharing mode to SharingMode.WITH and operation mode to OperationMode.ALL_OR_NONE */
	global SFDCAccessController() {
		// init the three access contorl instances to enforce sharing
		acws = new AccessControllerWithSharing();
		acwos = new AccessControllerWithoutSharing();
		acis = new AccessControllerInheritSharing();
		
		// init modes
		setSharingMode(SharingMode.WITH); // defaults to with sharing
		setOperationMode(OperationMode.ALL_OR_NONE); // defaults to all or none
	}
	
	/* This constructor allows you to set the sharing mode and operation mode */
	global SFDCAccessController(SharingMode smode, OperationMode omode) {
		this();
		
		setSharingMode(smode);
		setOperationMode(omode);
	}

	/* 
	 *  This function returns the instance object to use based on the current sharing mode set in smode.
	 */
	private AccessControllerInterface getACImpl() {
		if (smode == SharingMode.WITH)
			return acws;
		else if (smode == SharingMode.WITHOUT)
			return acwos;
		else // we always enforce smode to be a valid value - so no need to check it here again if null or incorrect value
			return acis;
	}
	
	global void setSharingMode(SharingMode smode) {
		if (smode == null)
			throw new AccessControlDmlException('SharingMode must not be null');
			
		if (smode == SharingMode.WITH || smode == SharingMode.WITHOUT || smode == SharingMode.INHERIT)
			this.smode = smode;
		else
			throw new AccessControlDmlException('Invalid value for SharingMode');
	}

	global void setOperationMode(OperationMode omode) {
		/* set operation mode into instance objects. 
		 * Note : sharing mode is set in the outter class, but this is set on the actual instance objects 
		 *  because that is where this mode is going to be used)
		 */
		acws.setOperationMode(omode);
		acwos.setOperationMode(omode);
		acis.setOperationMode(omode);
	}	

	/* Check to see if the user can create this object.
	 * If he can, depending on the operation mode do the following:
	 * 		BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.
	 *		ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.
	 * In addition throw an exception if the user does not have the CREATE permission on the object. 
	 */
	global void insertAsUser(SObject someObj, List<String> fieldsToSet) {
		// call insertAsUser using specific instance based on current sharing mode
		getACImpl().insertAsUser(someObj, fieldsToSet);
	}	

	/* Check to see if the user can update this object.
	 * If he can, depending on the operation mode do the following:
	 * 		BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.
	 *		ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception.
	 * In addition throw an exception if the user does not have the UPDATE permission on the object. 
	 */
	global void updateAsUser(SObject someObj, List<String> fieldsToUpdate) {
		// call updateAsUser using specific instance based on current sharing mode
		getACImpl().updateAsUser(someObj, fieldsToUpdate);
	}

	/* Check to see if the user can delete this object. Throw exception if not.
	 */
	global void deleteAsUser(SObject someObj) {
		// call deleteAsUser using specific instance based on current sharing mode
		getACImpl().deleteAsUser(someObj);
	}
	
	/* Return a list of sobject fields that are viewable by this user 
	 */ 
	public List<Schema.SObjectField> getViewableFields(SObject someObj) {
		return getACImpl().getViewableFields(someObj);
	}
        
	/* Returns a list of sobject fields that are updateable by this user.
	 */ 
	public List<Schema.SObjectField> getUpdateableFields(SObject someObj) {
		return getACImpl().getUpdateableFields(someObj);
	}
    
	/* Returns a list of sobject fields that are createable by this user.
	 */ 
	public List<Schema.SObjectField> getCreatableFields(SObject someObj) {
		return getACImpl().getCreatableFields(someObj);
	}
	
	/* This internal class does most of the actual CRUD/FLS work - you should never create instances of this class
	 * instead you should create instances of the three classes that inherit fomr this one which enfocre also sharing
	 */
	private virtual class AccessControllerInternal implements AccessControllerInterface {
	
		private OperationMode omode; // the current operation mode of this instance.
		
		// These four helper functions are just place holders. They are overwritten in the three sharing mode classes.
		private virtual List<SObject> dbQuery(String query) { return null; }
		private virtual void dbInsert(sObject obj) {}
		private virtual void dbUpdate(sObject obj) {}
		private virtual void dbDelete(sObject obj) {}
		
		private void setOperationMode(OperationMode omode) {
			if (omode == null)
				throw new AccessControlDmlException('OperationMode must not be null');
				
			if (omode == OperationMode.ALL_OR_NONE || omode == OperationMode.BEST_EFFORT)
				this.omode = omode;
			else
				throw new AccessControlDmlException('Invalid value for OperationMode');
		}	

		// Shortcut function
		public Map<String,Schema.SObjectField> getFieldMap(SObject someObj){
			return someObj.getSObjectType().getDescribe().fields.getMap();
		}

		/* This is used because the get*Fields() functions return lists of
		 * fields and not just their names as strings.  It returns a set
		 * so we can call contains()
		 */ 
		public Set<String> fieldsToStringSet(List<Schema.SObjectField> fields) {
			Set<String> fieldNames = new Set<String>{};
			for (Schema.SObjectField f:fields) {
				fieldNames.add(f.getDescribe().getName());
			}
			return fieldNames;
		}
    
		/* Return a list of sobject fields that are viewable by this user 
		 * (i.e. isAccessible() returns true)
		 * This is the optimized version when the fieldMap is already availabl
		 */
		public List<Schema.SObjectField> getViewableFields(SObject someObj,Map<String,Schema.SObjectField> fieldsMap) {
			List<Schema.SObjectField> fields = new List<Schema.SObjectField>{};
			for(String key:fieldsMap.keySet()) {
				if(fieldsMap.get(key).getDescribe().isAccessible()) {
					fields.add(fieldsMap.get(key));
				}
			}
			return fields;
		}
		
		/* Return a list of sobject fields that are viewable by this user 
		 */ 
		public List<Schema.SObjectField> getViewableFields(SObject someObj) {
			Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someObj);
			return getViewableFields(someObj,fieldsMap);
		}
        
		/* Returns a list of sobject fields that are updateable by this user.
		 * This is the optimized version when the fieldMap is already available
		 */ 
		public List<Schema.SObjectField> getUpdateableFields(SObject someObj,Map<String,Schema.SObjectField> fieldsMap) {
			List<Schema.SObjectField> fields = new List<Schema.SObjectField>{};
			for(String key:fieldsMap.keySet()) {
				if(fieldsMap.get(key).getDescribe().isUpdateable()) {
					fields.add(fieldsMap.get(key));
				}
			}
			return fields;
		}
		
		/* Returns a list of sobject fields that are updateable by this user.
		 */ 
		public List<Schema.SObjectField> getUpdateableFields(SObject someObj) {
			Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someObj);
			return getUpdateableFields(someObj,fieldsMap);
		}
    
		/* Returns a list of sobject fields that are createable by this user
		 * This is the optimized version when the fieldMap is already available
		 */ 
		public List<Schema.SObjectField> getCreatableFields(SObject someObj,Map<String,Schema.SObjectField> fieldsMap) {
			List<Schema.SObjectField> fields = new List<Schema.SObjectField>{};
			for(String key:fieldsMap.keySet()) {
				if(fieldsMap.get(key).getDescribe().isCreateable()) {
					fields.add(fieldsMap.get(key));
				}
			}
			return fields;
		}
		
		public List<Schema.SObjectField> getCreatableFields(SObject someObj) {
			Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someObj);
			return getCreatableFields(someObj,fieldsMap);
		}
		
		/* Check to see if the user can create this object.
		 * If he can, depending on the operation mode do the following:
		 * 		BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.
		 *		ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.
		 * In addition throw an exception if the user does not have the CREATE permission on the object. 
		 */
		public void insertAsUser(SObject devObj, List<String> fieldsToSet) {
			if (devObj == null || fieldsToSet == null || fieldsToSet.size() == 0)
				throw new AccessControlDmlException('null or empty parameter');
			
			Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
			if (d.isCreateable() == false) 
				throw new SFDCAccessControlException('Access Violation', 
														SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
														SFDCAccessControlException.ExceptionReason.NO_CREATE,
														d.getName(),
														null);

			Set<String> creatableFields = fieldsToStringSet(getCreatableFields(devObj, d.fields.getMap()));
			
			// start from a fresh sObject of same type and only set fields the user is allowed to set
			sObject cleanObj = devObj.getSObjectType().newSObject();

			// set all fields that were requested and the user has permission to set - throw an exception if a field was requested and user can't set and in ALL_OR_NONE mode			
			for (String fieldName : fieldsToSet) {
				if (creatableFields == null || creatableFields.contains(fieldName) == false) {
					// creatableFields is either null which means no fields are allowed to be set by user, or is not null but does not contain the current fieldName
					if (omode == OperationMode.ALL_OR_NONE)
						// if operation mode == ALL_OR_NONE - throw exception because user does not have permission to set fieldName
						throw new SFDCAccessControlException('Access Violation', 
											SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
											SFDCAccessControlException.ExceptionReason.NO_CREATE,
											d.getName(),
											fieldName);
				}
				else {
					// user has permission to set fieldName and it was request by the developer - so set it
					// if the developer did not set this field and it is required, we should get an exception 
					// when we set it here, or when we perform the actual insert.
					cleanObj.put(fieldName, devObj.get(fieldName));
				}
			}
			
			try {
				// call dbInsert() to enforce sharing rules if required
				dbInsert(cleanObj);
			} catch (Exception e) {
				throw new AccessControlDmlException('Failed to insert object');
			}
		}
		
		/* Check to see if the user can update this object.
		 * If he can, depending on the operation mode do the following:
		 * 		BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.
		 *		ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception.
		 * In addition throw an exception if the user does not have the UPDATE permission on the object. 
		 */
		public void updateAsUser(SObject devObj, List<String> fieldsToUpdate) {
			if (devObj == null || fieldsToUpdate == null || fieldsToUpdate.size() == 0)
				throw new AccessControlDmlException('null or empty parameter');
			
			Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
			if (d.isUpdateable() == false) 
				throw new SFDCAccessControlException('Access Violation', 
														SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
														SFDCAccessControlException.ExceptionReason.NO_UPDATE,
														d.getName(),
														null);
														
			Map<String,Schema.SObjectField> fieldsMap = d.fields.getMap();
			
			// first load the existing object as current user (enforcing sharing based on sharing mode)
			SObject cleanObj = getObject(devObj, fieldsMap);
			if (cleanObj == null)
				throw new SFDCAccessControlException('Record does not exist or not shared with current user', 
														SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
														SFDCAccessControlException.ExceptionReason.GENERIC,
														d.getName(),
														null);

			Set<String> updateableFields = fieldsToStringSet(getUpdateableFields(devObj,fieldsMap));
			
			// set all fields that were requested and the user has permission to update - throw an exception if a field was requested and user can't update and in ALL_OR_NONE mode			
			for (String fieldName : fieldsToUpdate) {
				if (updateableFields == null || updateableFields.contains(fieldName) == false) {
					// updateableFields is either null which means no fields are allowed to be set by user, or is not null but does not contain the current fieldName
					if (omode == OperationMode.ALL_OR_NONE)
						// if operation mode == ALL_OR_NONE - throw exception because user does not have permission to update fieldName
						throw new SFDCAccessControlException('Access Violation', 
											SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
											SFDCAccessControlException.ExceptionReason.NO_UPDATE,
											d.getName(),
											fieldName);
				}
				else {
					// user has permission to update fieldName and it was request by the developer - so update it
					cleanObj.put(fieldName, devObj.get(fieldName));
				}
			}
			
			try {
				// call dbUpdate() to enforce sharing rules if required
				dbUpdate(cleanObj);
			} catch (Exception e) {
				throw new AccessControlDmlException('Failed to update object');
			}
		}

		/* Check to see if the user can delete this object. Throw exception if not.
		 */
		public void deleteAsUser(SObject devObj) {
			if (devObj == null)
				throw new AccessControlDmlException('null parameter');
			
			Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
			if (d.isDeletable() == false) 
				throw new SFDCAccessControlException('Access Violation', 
														SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
														SFDCAccessControlException.ExceptionReason.NO_DELETE,
														d.getName(),
														null);

			try {
				// call dbDelete() to enforce sharing rules if required
				dbDelete(devObj);
			} catch (Exception e) {
				throw new AccessControlDmlException('Failed to delete object');
			}
		}
    
		/* Gets an object and all of its fields.  Note that this will probably break
		 * on objects with a huge number of fields.  It accepts fieldsMap as an 
		 * optimization.
		 *
		 * This is private because it doesn't not respect FLS, CRUD, or sharing and is only 
		 * used to get existing object to be used as a clean object before performing an updateAsUser
		 *
		 * Note: field names and object names (retrieved from the describe info) should be safe to add 
		 * to the SOQL as is, because they should only contain alphanumeric and under score
		 */ 
		private SObject getObject(sObject obj, Map<String,Schema.SObjectField> fieldsMap) {
			
			Set<String> allFields = fieldsMap.keySet();
			String Soql = 'SELECT ';
			Boolean emptyFields = true;
			
			// add all fields
			for (String field : allFields) {
			    Soql += field + ',';
			    emptyFields = false;
			}
			
			// make sure we added at least one field
			if (emptyFields == true)
				throw new SFDCAccessControlException('Query must contain at least one field', 
														SFDCAccessControlException.ExceptionType.GENERIC, 
														SFDCAccessControlException.ExceptionReason.GENERIC,
														obj.getSObjectType().getDescribe().getName(),
														null);
			
			// chop the extra , (We confirmed earlier that we had at least one field so the string will always end with ,)
			Soql = Soql.substring(0,Soql.length()-1);
			Soql += ' FROM ' + obj.getSObjectType().getDescribe().getName() + ' WHERE Id=\'' + String.escapeSingleQuotes(obj.Id) + '\'';
			
			List<SObject> res;
			
			try {
				// call dbQuery() to enforce sharing rules if required
				res = dbQuery(Soql);
			} catch (Exception e) {
				throw new AccessControlDmlException('Failed to query object');
			}
			
			if (res.isEmpty() == True) {
				return null;
			}
			else { 
				return res.get(0);
			}
		}
	}
	
}