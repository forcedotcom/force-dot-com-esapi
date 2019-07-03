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
    
    /**
     * SharingMode - this enum defines the sharing mode to be used.
     * <br>
     * You can set the sharing mode in the constructor or later using the setSharingMode() method.
     * If you use the default constructor, we will set it to WITH.
     */
    global enum SharingMode {
        /**
         * Will use the class instance that enforces "with sharing".
         */
        WITH, 
        /**
         * Will use the class instance that enforces "without sharing".
         */
        WITHOUT, 
        /**
         * Will use the class instance that just inherits from the class that calls this class.
         */
        INHERIT,
        /**
         * Will use the class instance that enforces "with sharing". Debugs results
         */
        WITH_DEBUG }

    /**
     * OperationMode - this enum defines the DB operations mode to be used.
     * <br>
     * You can set the operation mode in the constructor or later using the setOperatoinMode() method.
     * If you use the default constructor, we will set it to ALL_OR_NONE.
     */
    global enum OperationMode {
        /**
         * Will make sure all required fields have the proper permissions before any operation takes place.
         */
        ALL_OR_NONE,
        /**
         * Will only set fields that are allowed. Other fields will be omitted from operation, but operation will continue.
         */
        BEST_EFFORT}
    
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
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
        //private override Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField) { return Database.upsert(objs, externalIdField, arrayAllOrNoneParam); }
        private override Database.UpsertResult[] dbUpsert(sObject [] objs) { return Database.upsert(objs, arrayAllOrNoneParam); }
    }
    
    private without sharing class AccessControllerWithoutSharing extends AccessControllerInternal {
        private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
        //private override Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField) { return Database.upsert(objs, externalIdField, arrayAllOrNoneParam); }
        private override Database.UpsertResult[] dbUpsert(sObject [] objs) { return Database.upsert(objs, arrayAllOrNoneParam); }
    }
    
    private class AccessControllerInheritSharing extends AccessControllerInternal{
        private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
        //private override Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField) { return Database.upsert(objs, externalIdField, arrayAllOrNoneParam); }
        private override Database.UpsertResult[] dbUpsert(sObject [] objs) { return Database.upsert(objs, arrayAllOrNoneParam); }
    }

    private with sharing class AccessControllerWithSharingDebug extends AccessControllerInternal {
        private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
        //private override Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField) { return Database.upsert(objs, externalIdField, arrayAllOrNoneParam); }
        private override Database.UpsertResult[] dbUpsert(sObject [] objs) {
            System.debug('AccessControllerWithSharingDebug');
			Database.UpsertResult[] results = Database.upsert(objs, false); //arrayAllOrNoneParam
			integer index = 0;
			for(Database.UpsertResult ur : results) {
				if(!ur.isSuccess()) {
					SObject problemRecord = objs.get(index);
					string message = 'ID:' + ur.getId();
					for(Database.Error e : ur.getErrors()) {
						message += '\n Message:' + e.getMessage();
						message += '\n StatusCode:' + e.getStatusCode();
						message += '\n Fields:' + e.getFields();
						message += '\n index: ' + index;
						message += '\n oli: ' + problemRecord;
					}
					System.assert(false, message);
				}
				index++;
			}
            return results;
        }
    }

	/*
	 * Completely bypass the FLS checks and just directly perform DML actions
	 */
	private class AccessControllerOpenAccess extends AccessControllerInternal{
		private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
        //private override Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField) { return Database.upsert(objs, externalIdField, arrayAllOrNoneParam); }
        private override Database.UpsertResult[] dbUpsert(sObject [] objs) { return Database.upsert(objs, arrayAllOrNoneParam); }

		// Override methods from AccessControllerInterface to directly perform operations

		

		//global override SFDCAccessControlResults.InsertResults insertAsUser(SObject [] someObjs, List<String> fieldsToSet) {
			//Database.SaveResult [] results = Database.insert(someObjs);
			//return new SFDCAccessControlResults.InsertResults(someObjs, results);
		//}

		//global override SFDCAccessControlResults.UpdateResults updateAsUser(List<sObject> objs) {
			//Database.SaveResult [] results = Database.update(objs);
            //return new SFDCAccessControlResults.UpdateResults(objs, results);
		//}

		public override boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
			return true;
        }
        
        public override boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fieldNames) {
			return true;
		}

		public override boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNames) {
			return true;
		}

        public override boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldsToCreate, List<String> fieldsToUpdate) {
			return true;
		}

		public override SObject insertAsUser(SObject someObj, List<String> fieldsToSet) {
			dbInsert(someObj);
			return someObj;
		}

		public override SObject insertAsUser(SObject someObj, List<Schema.SObjectField> fieldsToSet) {
			dbInsert(someObj);
			return someObj;
		}

		public override SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<String> fieldsToSet) {
			Database.SaveResult[] results = dbInsert(devObjs);
			return new SFDCAccessControlResults.InsertResults(devObjs, results);
		}

		public override SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<Schema.SObjectField> fieldsToSet) {
			Database.SaveResult[] results = dbInsert(devObjs);
			return new SFDCAccessControlResults.InsertResults(devObjs, results);
		}

        // Directly update the sObjects. Special case they bypassing security checks within package.
        public SFDCAccessControlResults.UpdateResults updateAsUser(List<sObject> toUpdate) {
            Database.SaveResult [] results = dbUpdate(toUpdate);
            return new SFDCAccessControlResults.UpdateResults(toUpdate, results);
        }

		public override SObject updateAsUser(SObject devObj, List<String> fieldsToUpdate) {
			dbUpdate(devObj);
			return devObj;
		}

		public override SObject updateAsUser(SObject devObj, List<Schema.SObjectField> fieldsToUpdate) {
			dbUpdate(devObj);
			return devObj;
		}


		public override SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<String> fieldsToUpdate, Schema.SObjectType devType, List<String> fieldsToAlwaysUpdate) {
			Database.SaveResult [] results = dbUpdate(devMap.values());
            return new SFDCAccessControlResults.UpdateResults(devMap.values(), results);
		}

		public override SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<Schema.SObjectField> fieldsToUpdate, Schema.SObjectType devType) {
			Database.SaveResult [] results = dbUpdate(devMap.values());
            return new SFDCAccessControlResults.UpdateResults(devMap.values(), results);
		}

		public override void deleteAsUser(SObject devObj) {
			dbDelete(devObj);
		}

		public override SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] devObjs) {
			Database.DeleteResult[] results = dbDelete(devObjs);
			return new SFDCAccessControlResults.DeleteResults(results);
		}

        public override SFDCAccessControlResults.UpsertResults upsertAsUser(SObject [] devObjs) {
            Database.UpsertResult[] upsertResults = dbUpsert(devObjs);
            return new SFDCAccessControlResults.UpsertResults(devObjs, upsertResults);
        }
	}
    
    /* Helper interface : this interface will allow us to have a single interface defintion for all three sharing mode classes.
     *  This type is returned by the helper function getACImpl() so that no matter what object type it is actually returning,
     *  we can use it to call these same functions defined in the interface.
     */
    private interface AccessControllerInterface {
        SObject insertAsUser(SObject someObj, List<String> fieldsToSet);
        SObject insertAsUser(SObject someObj, List<Schema.SObjectField> fieldsToSet);
        SFDCAccessControlResults.InsertResults insertAsUser(SObject [] someObjs, List<String> fieldsToSet);
        SFDCAccessControlResults.InsertResults insertAsUser(SObject [] someObjs, List<Schema.SObjectField> fieldsToSet);
        
        SObject updateAsUser(SObject someObj, List<String> fieldsToUpdate);
        SObject updateAsUser(SObject someObj, List<Schema.SObjectField> fieldsToUpdate);
        SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<String> fieldsToUpdate, Schema.SObjectType objType, List<String> fieldsToAlwaysUpdate);
        SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<Schema.SObjectField> fieldsToUpdate, Schema.SObjectType objType);
                
        void deleteAsUser(SObject someObj);
        SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] someObjs);

        SFDCAccessControlResults.UpsertResults upsertAsUser(SObject [] devObjs);
        
        List<Schema.SObjectField> getViewableFields(SObjectType someType);
        List<Schema.SObjectField> getUpdateableFields(SObjectType someType);
        List<Schema.SObjectField> getCreatableFields(SObjectType someType);
        
        boolean isAuthorizedToView(Schema.SObjectType someType, List<String> fieldNames);
        boolean isAuthorizedToCreate(Schema.SObjectType someType, List<String> fieldNames);
        boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fieldNames);
		boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNames);
        boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNamesCreate, List<String> fieldNamesUpdate);
        
        boolean isAuthorizedToView(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        boolean isAuthorizedToCreate(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        
        boolean isAuthorizedToDelete(Schema.SObjectType someType);
    }
    
    /* instance variables */
	private AccessControllerOpenAccess openAccess; // anything goes access controller for when the org admin finds it all a bit to hard
    private AccessControllerWithSharing acws; // sharing access control object that was created with sharing
    private AccessControllerWithSharingDebug acwsDebug; // sharing access control object that was created with sharing and additional debug operations
    private AccessControllerWithoutSharing acwos; // sharing access control object that was created without sharing
    private AccessControllerInheritSharing acis; // sharing access control object that was created with sharing inherited from caller
    private SharingMode smode; // the current sharing mode of this instance. We will call the proper instance from the above three based on this value.
    
    /**
     * Default constructor - will set sharing mode to SharingMode.WITH, operation mode to OperationMode.ALL_OR_NONE, 
     *  and array operation mode to OperationMode.ALL_OR_NONE.
     */
    global SFDCAccessController() {
        // init the access control instances to enforce sharing
		openAccess = new AccessControllerOpenAccess();
        acws = new AccessControllerWithSharing();
        acwos = new AccessControllerWithoutSharing();
        acis = new AccessControllerInheritSharing();
        acwsDebug = new AccessControllerWithSharingDebug();
        
        // init modes
        setSharingMode(SharingMode.WITH); // defaults to with sharing
        setOperationMode(OperationMode.ALL_OR_NONE); // defaults to all or none
        setArrayOperationMode(OperationMode.ALL_OR_NONE); // defaults to all or none
    }
    
    /**
     * This constructor allows you to set the sharing mode and operation mode while using default for array operation mode.
     */
    global SFDCAccessController(SharingMode smode, OperationMode omode) {
        this();
        
        setSharingMode(smode);
        setOperationMode(omode);
        setArrayOperationMode(OperationMode.ALL_OR_NONE); // defaults to all or none
    }

    /**
     * This constructor allows you to set the sharing mode, operation mode, and array operation mode.
     */
    global SFDCAccessController(SharingMode smode, OperationMode omode, OperationMode oarrmode) {
        this();
        
        setSharingMode(smode);
        setOperationMode(omode);
        setArrayOperationMode(oarrmode);
    }

    /* 
     *  This function returns the instance object to use based on the current sharing mode set in smode.
     */
    private AccessControllerInterface getACImpl() {
        // This was connected to a custom setting
        boolean bypassSecurityModel = false;
		if(bypassSecurityModel) {
			// Allow bypass of the secuirity model if the admin can't grant sufficent profile or permission set to the package.
			return openAccess;
		} else if (smode == SharingMode.WITH) {
            return acws;
        } else if (smode == SharingMode.WITH_DEBUG) {
            return acwsDebug;
        } else if (smode == SharingMode.WITHOUT) {
            return acwos;
        } else { // we always enforce smode to be a valid value - so no need to check it here again if null or incorrect value
            return acis;
        }
    }

    /**
     * Set the sharing mode to use when calling this modules methods. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global void setSharingMode(SharingMode smode) {
        if (smode == null)
            throw new AccessControlDmlException('SharingMode must not be null');
            
        if (smode == SharingMode.WITH || smode == SharingMode.WITHOUT || smode == SharingMode.INHERIT || smode == SharingMode.WITH_DEBUG)
            this.smode = smode;
        else
            throw new AccessControlDmlException('Invalid value for SharingMode');
    }

    /**
     * Set the operation mode to use when calling this modules methods. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     ESAPI.accessController().setOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global void setOperationMode(OperationMode omode) {
        /* set operation mode into instance objects. 
         * Note : sharing mode is set in the outter class, but this is set on the actual instance objects 
         *  because that is where this mode is going to be used)
         */
		openAccess.setOperationMode(omode);
        acws.setOperationMode(omode);
        acwsDebug.setOperationMode(omode);
        acwos.setOperationMode(omode);
        acis.setOperationMode(omode);
    }   

    /**
     * Set the array operation mode to use when calling this modules methods. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     ESAPI.accessController().setArrayOperationMode(SFDCAccessController.OperationMode.ALL_OR_NONE);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global void setArrayOperationMode(OperationMode oarrmode) {
        /* set array operation mode into instance objects. 
         * Note : sharing mode is set in the outer class, but this is set on the actual instance objects 
         *  because that is where this mode is going to be used)
         */
		openAccess.setArrayOperationMode(oarrmode);
        acws.setArrayOperationMode(oarrmode);
        acwsDebug.setArrayOperationMode(oarrmode);
        acwos.setArrayOperationMode(oarrmode);
        acis.setArrayOperationMode(oarrmode);
    }

    /**
     * Insert the object with the context of the current user session.<br>
     * Depending on the operation mode do the following:<br>
     *    BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.<br>
     *    ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.<br>
     * In addition throw an exception if the user does not have the CREATE permission on the object.<br>
     * The function will return the new object that was created and inserted as SObject. Depending on<br> 
     * the current user permissions, the operation mode, and the fields you requested to set, this might<br>
     * not be all the fields you have in your original object. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = new Contact();
     *     c.LastName = 'Doe';
     *     c.FirstName = 'John';
     *     c = (Contact)ESAPI.accessController().insertAsUser(c, new List&lt;String&gt;{'LastName'});
     *     // Important note: c does not have the FirstName property set anymore, see function description for more info.
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE> 
     */
    global SObject insertAsUser(SObject someObj, List<String> fieldsToSet) {
        // call insertAsUser using specific instance based on current sharing mode
        return getACImpl().insertAsUser(someObj, fieldsToSet);
    }

	global SObject insertAsUser(SObject someObj) {
        List<String> fieldsToSet = new List<string>(someObj.getPopulatedFieldsAsMap().keySet());
        return getACImpl().insertAsUser(someObj, fieldsToSet);
    }

    // For a single sObject, switch the upsert to either an update or an insert
    public SObject upsertAsUser(SObject someObj) {
        if(someObj == null) {
            return null;
        }
        if(someObj.Id != null) {
            return updateAsUser(someObj);
        }
        else {
            return insertAsUser(someObj);
        }
    }

    public SFDCAccessControlResults.UpsertResults upsertAsUser(List<sObject> toUpsert, List<string> fieldsExcluded) {
        return upsertAsUser(toUpsert, fieldsExcluded, fieldsExcluded);
    }

    public SFDCAccessControlResults.UpsertResults upsertAsUser(List<sObject> toUpsert, List<String> fieldsExcludedFromCreate, List<String> fieldsExcludedFromUpdate) {
        if(toUpsert == null || toUpsert.isEmpty()) {
            return null;
        }

        Schema.SObjectType someType = toUpsert.getSObjectType();
        if(someType == null) {
            // We are dealing with list that potentially has multiple sObject types.
            System.debug(LoggingLevel.Debug, 'upsertAsUser() Unable to determine single sObject type from input List.');
            return upsertMultipleSObjectTypesAsUser(toUpsert, fieldsExcludedFromCreate, fieldsExcludedFromUpdate);
        }

        Set<String> fieldsToCreate = fieldsToUpdateFromSObject(toUpsert[0]);
        if(fieldsExcludedFromCreate != null && !fieldsExcludedFromCreate.isEmpty()) {
            fieldsToCreate.removeAll(fieldsExcludedFromCreate);
        }

        // TODO: What if fieldsExcludedFromUpdate == fieldsExcludedFromCreate? No need to clone...
        Set<String> fieldsToUpdate = fieldsToCreate.clone();
        if(fieldsExcludedFromUpdate != null && !fieldsExcludedFromUpdate.isEmpty()) {
            fieldsToUpdate.removeAll(fieldsExcludedFromUpdate);
        }

        if(isAuthorizedToUpsert(someType, new List<string>(fieldsToCreate), new List<string>(fieldsToUpdate))) {
            SFDCAccessControlResults.UpsertResults result = getACImpl().upsertAsUser(toUpsert);
            return result;
        } else {
            throw new SFDCAccessController.AccessControlDmlException('upsertAsUser() - access error upserting '+someType+' records. \nfieldsToCreate: '+fieldsToCreate+' \nfieldsToUpdate: ' + fieldsToUpdate);
        }
    }

    private SFDCAccessControlResults.UpsertResults upsertMultipleSObjectTypesAsUser(List<sObject> toUpsert, List<String> fieldsExcludedFromCreate, List<String> fieldsExcludedFromUpdate) {
        if(toUpsert == null || toUpsert.isEmpty()) {
            return null;
        }

        Schema.SObjectType someType = toUpsert.getSObjectType();
        System.assertEquals(null, someType, 'upsertMultipleSObjectTypesAsUser() SObjectType from List is not expected');
        
        // We are dealing with list that potentially has multiple sObject types.
        Map<Schema.SObjectType, List<sObject>> sObjectTypeToUniformListMap = new Map<Schema.SObjectType, List<sObject>>();
        Map<Schema.SObjectType, List<Integer>> sObjectTypeToUniformListSourceIndexesMap = new Map<Schema.SObjectType, List<Integer>>();

        Integer index = 0;
        for(sObject so : toUpsert) {
            Schema.SObjectType soType = so.getSObjectType();
            List<sObject> uniformList = null;
            List<Integer> uniformListIndexes = null;
            if(sObjectTypeToUniformListMap.containsKey(soType)) {
                uniformList = sObjectTypeToUniformListMap.get(soType);
                uniformListIndexes = sObjectTypeToUniformListSourceIndexesMap.get(soType);
            } else {
                // Make the list of the actual type
                String listType = 'List<' + soType + '>';
                uniformList = (List<SObject>)Type.forName(listType).newInstance();
                sObjectTypeToUniformListMap.put(soType, uniformList);

                uniformListIndexes = new List<Integer>();
                sObjectTypeToUniformListSourceIndexesMap.put(soType, uniformListIndexes);
            }
            uniformList.add(so);
            uniformListIndexes.add(index);

            //System.debug(LoggingLevel.Finer, 'upsertMultipleSObjectTypesAsUser() queued: ' + soType + ' at ' + index);

            index++;
        }

        if(sObjectTypeToUniformListMap.size() == 1) {
            // There is acutally only one type in the list.
            //System.debug(LoggingLevel.Debug, 'upsertMultipleSObjectTypesAsUser() processing single list of consistent sObject type');
            return upsertAsUser(sObjectTypeToUniformListMap.values()[0], fieldsExcludedFromCreate, fieldsExcludedFromUpdate);
        }

        // NOTE: The ordering of these results will likely differ from the order the sObjects were passed in!
        // This will make it difficult to extract the resulting IDs.
        
        Database.UpsertResult[] combinedUpsertResults = new Database.UpsertResult[toUpsert.size()];
        List<sObject> upsertedSObjects = new sObject[toUpsert.size()];
        for(Schema.SObjectType soType : sObjectTypeToUniformListMap.keySet()) {
            // Verify that this particular sObject has the required perms.
            List<SObject> soToUpsert = sObjectTypeToUniformListMap.get(soType);
            List<Integer> uniformListIndexes = sObjectTypeToUniformListSourceIndexesMap.get(soType);

            SFDCAccessControlResults.UpsertResults soResults = upsertAsUser(soToUpsert, fieldsExcludedFromCreate, fieldsExcludedFromUpdate);

            List<Database.UpsertResult> results = soResults.getResults();
            sObject[] upsertRecords = soResults.getUpsertedObjects();
            for(integer i = 0; i < upsertRecords.size(); i++) {
                integer inputIndex = uniformListIndexes[i];
                sObject upsertedRecord = upsertRecords[i];
                Database.UpsertResult upsertResult = results[i];

                combinedUpsertResults[inputIndex] = upsertResult;
                upsertedSObjects[inputIndex] = upsertedRecord;

                //System.debug(LoggingLevel.Finer, 'upsertMultipleSObjectTypesAsUser() upserted ' + upsertResult + ' at index ' + inputIndex + ' i:' + i);
            }
        }

        return new SFDCAccessControlResults.UpsertResults(upsertedSObjects, combinedUpsertResults);        
    }
    
    /**
     * Same as <a href="SFDCAccessController.html#insertAsUser%28SObject,%20List%3CString%3E%29">
     * <code>insertAsUser(SObject, List&lt;String&gt;)</code></a> 
     * but accepts a list of Schema.SObjectField instead of strings. Using this also avoids using sObject.fields 
     * member variable which is limited to 10 calls.<br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = new Contact();
     *     c.LastName = 'Doe';
     *     c.FirstName = 'John';
     *     c = (Contact)ESAPI.accessController().insertAsUser(c, new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     *     // Important note: c does not have the FirstName property set anymore, see function description for more info.
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global SObject insertAsUser(SObject someObj, List<Schema.SObjectField> fieldsToSet) {
        // call insertAsUser using specific instance based on current sharing mode
        return getACImpl().insertAsUser(someObj, fieldsToSet);
    }   
    
    /**
     * Insert the objects with the context of the current user session.<br>
     * Depending on the operation mode and array operation mode do:<br>
     *    operation mode:
     *       BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.<br>
     *       ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.<br>
     *    array operation mode:
     *       BEST_EFFORT - even if some objects are failing to insert, continue to insert the rest.<br>
     *       ALL_OR_NONE - if some objects are failing to insert, don't insert any.<br>
     * In addition throw an exception if the user does not have the CREATE permission on the object.<br>
     * Use the return value to get the SaveResult [] and the objects that were actually inserted into db.<br><br>
     * 
     * Note: You must provide this function an array of sObject of concrete type in order to use this function. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c1 = new Contact();
     *     c1.LastName = 'Doe1';
     *     Contact c2 = new Contact();
     *     c2.LastName = 'Doe2';
     *     Contact [] arr = new Contact[]{c1, c2};
     *     SFDCAccessControlResults.InsertResults res;
     *     res = ESAPI.accessController().insertAsUser(new Map&lt;ID, Contact&gt;(arr), new List&lt;String&gt;{'LastName'});
     *     arr = res.getInsertedObjects();
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     * 
     * @return A SFDCAccessControlResults.InsertResults object.
     */
    global SFDCAccessControlResults.InsertResults insertAsUser(SObject [] someObjs, List<String> fieldsToSet) {
        // call insertAsUser using specific instance based on current sharing mode
        return getACImpl().insertAsUser(someObjs, fieldsToSet);
    }

	global SFDCAccessControlResults.InsertResults insertAsUser(List<sObject> someObjs) {
        
        if(someObjs == null || someObjs.isEmpty()) {
            SObject[] devObjs = new List<SObject>();
			Database.SaveResult[] results = new List<Database.SaveResult>();
			return new SFDCAccessControlResults.InsertResults(devObjs, results);
        }

		// Note: This is only going to build up the field set for the first sObject in the collection.
		// If different sObjects have different fields then they will be ignored.
		Set<String> keySet = someObjs.get(0).getPopulatedFieldsAsMap().keySet();
		List<String> fieldsToUpdate = new List<string>(keySet);
		System.debug('insertAsUser fieldsToUpdate:' + fieldsToUpdate);

        return getACImpl().insertAsUser(someObjs, fieldsToUpdate);
    }

    /**
     * Same as <a href="SFDCAccessController.html#insertAsUser%28sObject[],%20List%3CString%3E%29">
     * <code>insertAsUser(sObject[], List&lt;String&gt;)</code></a> 
     * but accepts a list of Schema.SObjectField instead of strings. Using this also avoids using sObject.fields 
     * member variable which is limited to 10 calls.<br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c1 = new Contact();
     *     c1.LastName = 'Doe1';
     *     Contact c2 = new Contact();
     *     c2.LastName = 'Doe2';
     *     Contact [] arr = new Contact[]{c1, c2};
     *     SFDCAccessControlResults.InsertResults res;   
     *     res = ESAPI.accessController().insertAsUser(new Map&lt;ID, Contact&gt;(arr), new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     *     arr = res.getInsertedObjects();
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global SFDCAccessControlResults.InsertResults insertAsUser(SObject [] someObjs, List<Schema.SObjectField> fieldsToSet) {
        // call insertAsUser using specific instance based on current sharing mode
        return getACImpl().insertAsUser(someObjs, fieldsToSet);
    }

    /**
     * Update the object with the context of the current user session.<br>
     * Depending on the operation mode do the following:<br>
     *    BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.<br>
     *    ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception.<br>
     * In addition throw an exception if the user does not have the UPDATE permission on the object.<br>
     * The function will return the updated object that was actually used to update the db. Depending on<br> 
     * the current user permissions, the operation mode, and the fields you requested to update, this might<br>
     * not be all the fields you have in your original object. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     c.LastName = 'Doe2';
     *     c.FirstName = 'John';
     *     c = (Contact)ESAPI.accessController().updateAsUser(c, new List&lt;String&gt;{'LastName'});
     *     // Important note: c does not have the FirstName property set anymore, see function description for more info.
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global SObject updateAsUser(SObject someObj, List<String> fieldsToUpdate) {
        // call updateAsUser using specific instance based on current sharing mode
        return getACImpl().updateAsUser(someObj, fieldsToUpdate);
    }

	global SObject updateAsUser(SObject someObj) {
        Set<String> keySet = fieldsToUpdateFromSObject(someObj);

		List<String> fieldsToSet = new List<string>(keySet);
		System.debug('updateAsUser fieldsToSet:' + fieldsToSet);
        return getACImpl().updateAsUser(someObj, fieldsToSet);
    }

	// Find the sObjects fields that should be updated.
	public Set<String> fieldsToUpdateFromSObject(SObject someObj) {

		Map<String, Schema.SObjectField> fieldMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(someObj.getSObjectType());

		Set<String> keySet = someObj.getPopulatedFieldsAsMap().keySet().clone();
		// It is important to clone the set here to allow adds and to avoid changing the underlying Map.
		// https://salesforce.stackexchange.com/a/207393?noredirect=1

		// Id and other common system only fields shouldn't be included in the fields to update check.
		keySet.remove('Id');
		keySet.remove('SystemModstamp');
		keySet.remove('LastModifiedDate');
		keySet.remove('LastModifiedById');
		keySet.remove('CreatedDate');
		keySet.remove('CreatedById');
        keySet.remove('IsDeleted');
		keySet.remove('Owner');
		for(string fieldName : keySet) {
			if(fieldName.endsWith('__r')) {
				keySet.remove(fieldName);
				continue;
			}
			// Code within the managed package won't see namespace in describe
			//string lookupFieldName = fieldName.replace('namespace__', '');
            // Code within the managed package WILL see namespace in describe (v43.0)
            string lookupFieldName = fieldName;

			//System.debug(LoggingLevel.Debug, 'SFDCAccessController.fieldsToUpdateFromSObject() Checking: ' + fieldName + ' with lookupFieldName:' + lookupFieldName);

			Schema.SObjectField fieldInfo = fieldMap.get(lookupFieldName);
			if(fieldInfo == null) {
				Schema.DescribeSObjectResult d = someObj.getSObjectType().getDescribe(); 
				Map<String, Schema.SObjectField> fieldMap2 = d.fields.getMap();
				lookupFieldName = lookupFieldName.toLowerCase();
                fieldInfo = fieldMap2.get(lookupFieldName);

				//System.assertNotEquals(null, fieldInfo, 'SFDCAccessController.fieldsToUpdateFromSObject() Failed to find field info for ' + lookupFieldName + '. ' + fieldMap);
				if(fieldInfo == null) {
					// Maybe it is a native referece (no __r) but can't be resolved by the relationshipName?
                    string referenceFieldName = lookupFieldName + 'Id';
                    fieldInfo = fieldMap2.get(referenceFieldName);
                    if(fieldInfo != null) {
                        Schema.DescribeFieldResult describe = fieldInfo.getDescribe();
                        if(describe.type == DisplayType.REFERENCE && describe.relationshipName == lookupFieldName) {
                            continue;
                        }
                    }
                    
                    //System.debug(LoggingLevel.Error, 'SFDCAccessController.fieldsToUpdateFromSObject() Failed to find field info for ['+d.getName()+'].[' + lookupFieldName + '].\n fieldMap:' + fieldMap.keySet() + ' keyset: ' + fieldMap2.keyset());
					//System.assert(!Test.isRunningTest(), 'SFDCAccessController.fieldsToUpdateFromSObject() Failed to find field info for ['+d.getName()+'].[' + lookupFieldName + '].\n fieldMap:' + fieldMap.keySet());
                    //for(string key : fieldMap2.keySet()) {
                        //System.debug(LoggingLevel.Error, 'SFDCAccessController.fieldsToUpdateFromSObject() ['+key+']');
                    //}

					continue;
				}
			}
			
			Schema.DescribeFieldResult dfr = fieldInfo.getDescribe();
			if(dfr.isCalculated()) {
				// Exclude formula fields
				//System.debug(LoggingLevel.Debug, 'SFDCAccessController.fieldsToUpdateFromSObject() Excluding Calculated Field ' + fieldName);
				keySet.remove(fieldName);
				continue;
			}
		}
		return keySet;
	}

    /**
     * Same as <a href="SFDCAccessController.html#updateAsUser%28SObject,%20List%3CString%3E%29">
     * <code>updateAsUser(SObject, List&lt;String&gt;)</code></a> 
     * but accepts a list of Schema.SObjectField instead of strings. Using this also avoids using sObject.fields 
     * member variable which is limited to 10 calls.<br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     c.LastName = 'Doe2';
     *     c.FirstName = 'John';
     *     c = (Contact)ESAPI.accessController().updateAsUser(c, new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     *     // Important note: c does not have the FirstName property set anymore, see function description for more info.
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global SObject updateAsUser(SObject someObj, List<Schema.SObjectField> fieldsToUpdate) {
        // call updateAsUser using specific instance based on current sharing mode
        return getACImpl().updateAsUser(someObj, fieldsToUpdate);
    }
    
	global SFDCAccessControlResults.UpdateResults updateAsUser(List<sObject> objs) {
        if(objs == null) {
            throw new AccessControlDmlException('objs must not be null');
        }

        AccessControllerInterface aci = getACImpl();
        if(aci instanceOf AccessControllerOpenAccess) {
            // Bypass when not enforcing FLS due to configuration
            AccessControllerOpenAccess acoa = (AccessControllerOpenAccess)aci;
            return acoa.updateAsUser(objs);
        }

		Map<ID, sObject> objMap = convertListToStronglyTypedMap(objs);

		// Note: This is only going to build up the field set for the first sObject in the collection.
		// If different sObjects have different fields then they will be ignored.
		Schema.SObjectType objType = objs.get(0).getSObjectType();

		Set<String> keySet = fieldsToUpdateFromSObject(objs.get(0));

		List<String> fieldsToUpdate = new List<string>(keySet);
		System.debug(LoggingLevel.FINER, 'updateAsUser fieldsToUpdate:' + fieldsToUpdate);
		System.assertNotEquals(0, fieldsToUpdate.size(), 'SFDCAccessController.fieldsToUpdate() no fields found to update');

		List<String> fieldsToAlwaysUpdate = new List<String>();

        return aci.updateAsUser(objMap, fieldsToUpdate, objType, fieldsToAlwaysUpdate);
    }

	global SFDCAccessControlResults.UpdateResults updateAsUser(List<sObject> objs, List<String> fieldsToUpdate) {
		return updateAsUser(objs, fieldsToUpdate, new List<String>());
	}

	public SFDCAccessControlResults.UpdateResults updateAsUser(List<sObject> objs, List<String> fieldsToUpdate, List<String> fieldsToAlwaysUpdate) {
        
		Map<ID, sObject> objMap = convertListToStronglyTypedMap(objs);

        System.assert(!objs.isEmpty(), 'updateAsUser() input objs was empty');
		Schema.SObjectType objType = objs.get(0).getSObjectType();	

        return getACImpl().updateAsUser(objMap, fieldsToUpdate, objType, fieldsToAlwaysUpdate);
    }

	private Map<Id, sObject> convertListToStronglyTypedMap(List<sObject> inputList) {
        // This won't work if the inputList is of a generic sObject type
		Schema.SObjectType listObjType = inputList.getSObjectType();
        if(listObjType == null) {
            // Check if all the sObjects are of the same type, if they are, use that.
            Schema.SObjectType commonOjType = null;
            for(sObject sObl : inputList) {
                Schema.SObjectType sOjType = sObl.getSObjectType();
                if(commonOjType == null) {
                    commonOjType = sOjType;
                } else if (sOjType != commonOjType) {
                    commonOjType = null;
                    break;
                }
            }
            if(commonOjType != null) {
                listObjType = commonOjType;
            }
        }

        if(listObjType == null) {
            // We are dealing with list that potentially has multiple sObject types.
            System.debug(LoggingLevel.Debug, 'convertListToStronglyTypedMap() Unable to determine single sObject type from input List.');
            //return updateMultipleSObjectTypesAsUser(inputList);

            // Temp fix is to set AdBookSettings.BypassSecurityModelChecks = true;

            throw new AccessControlDmlException('listObjType must not be null. Likely multiple sObject Types. \n inputList: ' + inputList);
        }

		// Seems to work. Consider listObjType.getDescribe().getName()
		Type mapType = Type.forName('Map<Id, '+listObjType+'>');
        if(mapType == null) {
            throw new AccessControlDmlException('mapType must not be null. \n listObjType: ' + listObjType);
        }
    
		Map<Id, sObject> outputMap = (Map<Id, sObject>)mapType.newInstance();
		outputMap.putAll(inputList);
		System.assertEquals(listObjType, outputMap.getSObjectType());

		return outputMap;
	}

    /**
     * Update the objects with the context of the current user session.<br>
     * Depending on the operation mode and array operation mode do:<br>
     *    operation mode:
     *       BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.<br>
     *       ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception.<br>
     *    array operation mode:
     *       BEST_EFFORT - even if some objects are failing to update, continue to update the rest.<br>
     *       ALL_OR_NONE - if some objects are failing to update, don't update any.<br>
     * In addition throw an exception if the user does not have the UPDATE permission on the object.<br>
     * Use the return value to get the SaveResult [] and the objects that were actually inserted into db.<br><br>
     * 
     * Note: You must provide this function a map of sObject of concrete type in order to use this function. We chose a map and not an array 
     *  to increase performance. We couldn't internally convert from an array into a map because of Apex restrictions on maps with
     *  generic sObject type values. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact [] arr = [select LastName,id from Contact];
     *     SFDCAccessControlResults.UpdateResults res;
     *     res = ESAPI.accessController().updateAsUser(new Map&lt;ID, Contact&gt;(arr), new List&lt;String&gt;{'LastName'});
     *     arr = res.getUpdatedObjects();
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     * 
     * @return A SFDCAccessControlResults.UpdateResults object.
     */
    global SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<String> fieldsToUpdate) {

		List<String> fieldsToAlwaysUpdate = new List<String>();
        // call updateAsUser using specific instance based on current sharing mode
        return getACImpl().updateAsUser(objMap, fieldsToUpdate, objMap.getSObjectType(), fieldsToAlwaysUpdate);
    }

    /**
     * Same as <a href="SFDCAccessController.html#updateAsUser%28Map%3CID,%20sObject%3E,%20List%3CString%3E%29">
     * <code>updateAsUser(Map&lt;ID, sObject&gt;, List&lt;String&gt;)</code></a> 
     * but accepts a list of Schema.SObjectField instead of strings. Using this also avoids using sObject.fields 
     * member variable which is limited to 10 calls.<br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact [] arr = [select LastName,id from Contact];
     *     SFDCAccessControlResults.UpdateResults res;
     *     res = ESAPI.accessController().updateAsUser(new Map&lt;ID, Contact&gt;(arr), new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     *     arr = res.getUpdatedObjects();
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<Schema.SObjectField> fieldsToUpdate) {
        // call updateAsUser using specific instance based on current sharing mode
        return getACImpl().updateAsUser(objMap, fieldsToUpdate, objMap.getSObjectType());
    }

    /** 
     * Delete the object with the context of the current user session. Throw exception if user can't delete this object. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     ESAPI.accessController().deleteAsUser(c);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */
    global void deleteAsUser(SObject someObj) {
        // call deleteAsUser using specific instance based on current sharing mode
        getACImpl().deleteAsUser(someObj);
    }
    
    /**
     * Delete the objects with the context of the current user session.<br>
     * Depending on the array operation mode do:<br>
     *    array operation mode:
     *       BEST_EFFORT - even if some objects are failing to delete, continue to delete the rest.<br>
     *       ALL_OR_NONE - if some objects are failing to delete, don't delete any.<br>
     * In addition throw an exception if the user does not have the DELETE permission on the object.<br><br>
     * 
     * Note: You must provide this function an array of sObject of concrete type in order to use this function. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact [] arr = [select LastName,id from Contact];
     *     SFDCAccessControlResults.DeleteResults res;
     *     res = ESAPI.accessController().deleteAsUser(arr);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     * 
     * @return A SFDCAccessControlResults.DeleteResults object.
     */
    global SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] someObjs) {
        // call deleteAsUser using specific instance based on current sharing mode
        return getACImpl().deleteAsUser(someObjs);
    }
    
    /**
     * Return a list of sobject fields that are viewable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     Schema.SObjectField[] viewableFields = ESAPI.accessController().getViewableFields(c);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE> 
     * @deprecated
     */     
    global List<Schema.SObjectField> getViewableFields(SObject someObj) {
        return getACImpl().getViewableFields(someObj.getSObjectType());
    }       
        
    /**
     * Return a list of sobject fields that are viewable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Schema.SObjectField[] viewableFields = ESAPI.accessController().getViewableFields(Contact.getSObjectType());
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE> 
     */     
    global List<Schema.SObjectField> getViewableFields(SObjectType someType) {
        return getACImpl().getViewableFields(someType);
    }
        
    /**
     * Return a list of sobject fields that are updateable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     Schema.SObjectField[] updateableFields = ESAPI.accessController().getUpdateableFields(c);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     * @deprecated
     */ 
    global List<Schema.SObjectField> getUpdateableFields(SObject someObj) {
        return getACImpl().getUpdateableFields(someObj.getSObjectType());
    }

    /**
     * Return a list of sobject fields that are updateable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Schema.SObjectField[] updateableFields = ESAPI.accessController().getUpdateableFields(Contact.getSObjectType());
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global List<Schema.SObjectField> getUpdateableFields(SObjectType someType) {
        return getACImpl().getUpdateableFields(someType);
    }
    
    /**
     * Returns a list of sobject fields that are createable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Contact c = (Contact)stdController.getRecord();
     *     Schema.SObjectField[] createableFields = ESAPI.accessController().getCreatableFields(c);
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     * @deprecated
     */ 
    global List<Schema.SObjectField> getCreatableFields(SObject someObj) {
        return getACImpl().getCreatableFields(someObj.getSObjectType());
    }

    /**
     * Returns a list of sobject fields that are createable by the current user session. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     Schema.SObjectField[] createableFields = ESAPI.accessController().getCreatableFields(Contact.getSObjectType());
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global List<Schema.SObjectField> getCreatableFields(SObjectType someType) {
        return getACImpl().getCreatableFields(someType);
    }

    /**
     * Returns true if the current user has view permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canView = ESAPI.accessController().isAuthorizedToView(Contact.getSObjectType(), new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToView(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
        return getACImpl().isAuthorizedToView(someType, fields);
    }

    /**
     * Returns true if the current user has view permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canView = ESAPI.accessController().isAuthorizedToView(Contact.getSObjectType(), new List&lt;String&gt;{'LastName'});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToView(Schema.SObjectType someType, List<String> fields) {
        return getACImpl().isAuthorizedToView(someType, fields);
    }

    /**
     * Returns true if the current user has create permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canCreate = ESAPI.accessController().isAuthorizedToCreate(Contact.getSObjectType(), new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToCreate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
        return getACImpl().isAuthorizedToCreate(someType, fields);
    }
    
    /**
     * Returns true if the current user has create permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canCreate = ESAPI.accessController().isAuthorizedToCreate(Contact.getSObjectType(), new List&lt;String&gt;{'LastName'});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToCreate(Schema.SObjectType someType, List<String> fields) {
        return getACImpl().isAuthorizedToCreate(someType, fields);
    }
    
    /**
     * Returns true if the current user has update permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canUpdate = ESAPI.accessController().isAuthorizedToUpdate(Contact.getSObjectType(), new List&lt;Schema.SObjectField&gt;{Contact.LastName});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
        return getACImpl().isAuthorizedToUpdate(someType, fields);
    }
    
    /**
     * Returns true if the current user has update permissions on the given object type and fields. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canUpdate = ESAPI.accessController().isAuthorizedToUpdate(Contact.getSObjectType(), new List&lt;String&gt;{'LastName'});
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fields) {
        return getACImpl().isAuthorizedToUpdate(someType, fields);
    }

	global boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fields) {
		return getACImpl().isAuthorizedToUpsert(someType, fields);
	}

    public boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNamesCreate, List<String> fieldNamesUpdate) {
        return getACImpl().isAuthorizedToUpsert(someType, fieldNamesCreate, fieldNamesUpdate);
    }

    /**
     * Returns true if the current user has delete permissions on the given object type. <br><br>
     * 
     * Example:<br>
     * <PRE>
     * try {
     *     boolean canDelete = ESAPI.accessController().isAuthorizedToDelete(Contact.getSObjectType());
     * } catch (SFDCAccessControlException e) {
     *     // error handling
     * }
     * </PRE>
     */ 
    global boolean isAuthorizedToDelete(Schema.SObjectType someType) {
        return getACImpl().isAuthorizedToDelete(someType);
    }
    
    /* This internal class does most of the actual CRUD/FLS work - you should never create instances of this class
     * instead you should create instances of the three classes that inherit fomr this one which enfocre also sharing
     */
    private abstract class AccessControllerInternal implements AccessControllerInterface {
    
        private OperationMode omode; // the current operation mode of this instance.
        private Boolean arrayAllOrNoneParam; // the current array operation mode param of this instance. (as provided to the database methods second argument)
        
        // These db... helper functions are just place holders. They are overwritten in the three sharing mode classes.
        private abstract List<SObject> dbQuery(String query);
        private abstract void dbInsert(sObject obj);
        private abstract Database.SaveResult[] dbInsert(sObject [] objs);
        private abstract void dbUpdate(sObject obj);
        private abstract Database.SaveResult[] dbUpdate(sObject [] objs);
        private abstract void dbDelete(sObject obj);
        private abstract Database.DeleteResult[] dbDelete(sObject [] objs);

        // Won't work. Results in a "Upsert with a field specification requires a concrete SObject type" compile error
        //private abstract Database.UpsertResult[] dbUpsert(sObject [] objs, Schema.SObjectField externalIdField);
        private abstract Database.UpsertResult[] dbUpsert(sObject [] objs);
        
        private void setOperationMode(OperationMode omode) {
            if (omode == null)
                throw new AccessControlDmlException('OperationMode must not be null');
                
            if (omode == OperationMode.ALL_OR_NONE || omode == OperationMode.BEST_EFFORT)
                this.omode = omode;
            else
                throw new AccessControlDmlException('Invalid value for OperationMode');
        }
        
        private void setArrayOperationMode(OperationMode oarrmode) {
            if (oarrmode == null)
                throw new AccessControlDmlException('OperationMode must not be null');
                
            if (oarrmode == OperationMode.ALL_OR_NONE)
                this.arrayAllOrNoneParam = true;
            else if (oarrmode == OperationMode.BEST_EFFORT)
                this.arrayAllOrNoneParam = false;
            else
                throw new AccessControlDmlException('Invalid value for OperationMode');
        }   

        // Shortcut function
        public Map<String,Schema.SObjectField> getFieldMap(SObjectType someType){
            return SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(someType);
        }

        /* This is used because the get*Fields() functions return lists of
         * fields and not just their names as strings.  It returns a set
         * so we can call contains()
         */ 
        public Set<String> fieldsToStringSet(List<Schema.SObjectField> fields) {
            Set<String> fieldNames = new Set<String>{};
            for (Schema.SObjectField f:fields) {
                fieldNames.add(f.getDescribe().getName().toLowerCase());
            }
            return fieldNames;
        }
    
        /* Return a list of sobject fields that are viewable by this user 
         * (i.e. isAccessible() returns true)
         * This is the optimized version when the fieldMap is already available
         */
        public List<Schema.SObjectField> getViewableFields(Map<String,Schema.SObjectField> fieldsMap) {
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
        public List<Schema.SObjectField> getViewableFields(SObjectType someType) {
            Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someType);
            return getViewableFields(fieldsMap);
        }
        
        public boolean isAuthorizedToView(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
            // check at object-level first
            if (!someType.getDescribe().isAccessible()){
                return false;
            }
            
            // check each field
            for (Schema.SObjectField f : fields) {
                if (!f.getDescribe().isAccessible()){
                    return false;
                }
            }
            return true;
        }
        
        public boolean isAuthorizedToView(Schema.SObjectType someType, List<String> fieldNames) {
            Schema.DescribeSObjectResult objDesc = someType.getDescribe();
            if (!objDesc.isAccessible()){
                return false;
            }
            Map<String, Schema.SObjectField> fMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(someType);
            for (String f : fieldNames) {
                Schema.SObjectField sObjectFld = fMap.get(f);
                if (sObjectFld == null) {
                    throw new SFDCAccessControlException('Field not found', 
                                                            SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, 
                                                            SFDCAccessControlException.ExceptionReason.GENERIC,
                                                            objDesc.getName(),
                                                            f);
                }
                if (!sObjectFld.getDescribe().isAccessible()){
                    return false;
                }
            }
            return true;
        }
       
        public virtual boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
            // check at object-level first
            if (!someType.getDescribe().isUpdateable()){
				//System.debug(LoggingLevel.Warn, 'isAuthorizedToUpdate() someType:' + someType + ' is not updateable');
                return false;
            }
            
            // check each field
            for (Schema.SObjectField f : fields) {
                if (!f.getDescribe().isUpdateable()){
					//System.debug(LoggingLevel.Warn, 'isAuthorizedToUpdate() someType:' + someType + ' f:' +f+ ' is not updateable');
                    return false;
                }
            }
            return true;
        }
        
        public virtual boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fieldNames) {
            Schema.DescribeSObjectResult objDesc = someType.getDescribe();
            if(!objDesc.isUpdateable()){
				//System.debug(LoggingLevel.Warn, 'isAuthorizedToUpdate() someType:' + someType + ' is not updateable');
                return false;
            }
            Map<String, Schema.SObjectField> fMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(someType);
            for (String f : fieldNames) {
                Schema.SObjectField sObjectFld = fMap.get(f);
                if (sObjectFld == null) {
                    throw new SFDCAccessControlException('Field not found', 
                                                            SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, 
                                                            SFDCAccessControlException.ExceptionReason.GENERIC,
                                                            objDesc.getName(),
                                                            f);
                }
                if (!sObjectFld.getDescribe().isUpdateable()){
					//System.debug(LoggingLevel.Warn, 'isAuthorizedToUpdate() someType:' + someType + ' sObjectFld:' +sObjectFld+ ' is not updateable');
                    return false;
                }
            }
            return true;
        }

		public virtual boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNames) {
			return isAuthorizedToUpsert(someType, fieldNames, fieldNames);
		}

        public virtual boolean isAuthorizedToUpsert(Schema.SObjectType someType, List<String> fieldNamesCreate, List<String> fieldNamesUpdate) {
            return isAuthorizedToCreate(someType, fieldNamesCreate) && isAuthorizedToUpdate(someType, fieldNamesUpdate);
        }

        public virtual SFDCAccessControlResults.UpsertResults upsertAsUser(SObject[] devObjs) {
            //System.debug(LoggingLevel.Finest, 'upsertAsUser: ' + devObjs);
            List<Database.UpsertResult> results = dbUpsert(devObjs);
            return new SFDCAccessControlResults.UpsertResults(devObjs, results);
        }
        
        /* Returns a list of sobject fields that are updateable by this user.
         * This is the optimized version when the fieldMap is already available
         */ 
        public List<Schema.SObjectField> getUpdateableFields(Map<String,Schema.SObjectField> fieldsMap) {
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
        public List<Schema.SObjectField> getUpdateableFields(SObjectType someType) {
            Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someType);
            return getUpdateableFields(fieldsMap);
        }
    
        /* Returns a list of sobject fields that are createable by this user
         * This is the optimized version when the fieldMap is already available
         */ 
        public List<Schema.SObjectField> getCreatableFields(Map<String,Schema.SObjectField> fieldsMap) {
            List<Schema.SObjectField> fields = new List<Schema.SObjectField>{};
            for(String key:fieldsMap.keySet()) {
                if(fieldsMap.get(key).getDescribe().isCreateable()) {
                    fields.add(fieldsMap.get(key));
                }
            }
            return fields;
        }
        
        public List<Schema.SObjectField> getCreatableFields(SObjectType someType) {
            Map<String,Schema.SObjectField> fieldsMap = getFieldMap(someType);
            return getCreatableFields(fieldsMap);
        }
        
        public boolean isAuthorizedToCreate(Schema.SObjectType someType, List<String> fieldNames) {
            System.assertNotEquals(null, someType, 'isAuthorizedToCreate() SObjectType is required');
            Schema.DescribeSObjectResult objDesc = someType.getDescribe();
            if (!objDesc.isCreateable()){
				//System.debug(LoggingLevel.Warn, 'isAuthorizedToCreate() someType:' + someType + ' is not creatable');
                return false;
            }
            Map<String, Schema.SObjectField> fMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(someType);
            for (String f : fieldNames) {
                Schema.SObjectField sObjectFld = fMap.get(f);
                if (sObjectFld == null) {
                    //System.debug(LoggingLevel.Error, 'fmap: ' + Json.serializePretty(fMap.keyset()));
                    throw new SFDCAccessControlException('Field not found', 
                                                            SFDCAccessControlException.ExceptionType.FIELD_NOT_FOUND, 
                                                            SFDCAccessControlException.ExceptionReason.GENERIC,
                                                            objDesc.getName(),
                                                            f);
                }
                if (!sObjectFld.getDescribe().isCreateable()){
					//System.debug(LoggingLevel.Warn, 'isAuthorizedToCreate() someType:' + someType + ' sObjectFld:' +sObjectFld+' is not creatable');
                    return false;
                }
            }
            return true;
        }
        
        public boolean isAuthorizedToCreate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
            // check at object-level first
            if (!someType.getDescribe().isCreateable()){
				//System.debug(LoggingLevel.Warn, 'isAuthorizedToCreate() someType:' + someType + ' is not creatable');
                return false;
            }
            
            // check each field
            for (Schema.SObjectField f : fields) {
                if (!f.getDescribe().isCreateable()){
					//System.debug(LoggingLevel.Warn, 'isAuthorizedToCreate() someType:' + someType + ' sObjectFld:' +f+' is not creatable');
                    return false;
                }
            }
            return true;
        }
		        
        /* Check to see if the user can create this object.
         * If he can, depending on the operation mode do the following:
         *      BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.
         *      ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.
         * In addition throw an exception if the user does not have the CREATE permission on the object.
         * Returns the cleanObj created and inserted into db. 
         */
        public virtual SObject insertAsUser(SObject devObj, List<String> fieldsToSet) {
            if (devObj == null || fieldsToSet == null || fieldsToSet.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
            if (d.isCreateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                        d.getName(),
                                                        null);

            Map<String, Schema.SObjectField> fieldMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(devObj.getSObjectType()); // potentially saves a fields call below
            Set<String> creatableFields = fieldsToStringSet(getCreatableFields(fieldMap));
            
            // start from a fresh sObject of same type and only set fields the user is allowed to set
            sObject cleanObj = devObj.getSObjectType().newSObject();

            // set all fields that were requested and the user has permission to set - throw an exception if a field was requested and user can't set and in ALL_OR_NONE mode           
            for (String fieldName : fieldsToSet) {
                fieldName = fieldName.toLowerCase();
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
            return cleanObj;
        }
        
        /* Same as insertAsUser(SObject, List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public virtual SObject insertAsUser(SObject devObj, List<Schema.SObjectField> fieldsToSet) {
            if (devObj == null || fieldsToSet == null || fieldsToSet.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
            if (d.isCreateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                        d.getName(),
                                                        null);

            // start from a fresh sObject of same type and only set fields the user is allowed to set
            sObject cleanObj = devObj.getSObjectType().newSObject();

            // set all fields that were requested and the user has permission to set - throw an exception if a field was requested and user can't set and in ALL_OR_NONE mode           
            for (Schema.SObjectField field : fieldsToSet) {
                if (field.getDescribe().isCreateable() == false) {
                    // field is not allowed to be created by current user
                    if (omode == OperationMode.ALL_OR_NONE)
                        // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to set fieldName
                        throw new SFDCAccessControlException('Access Violation', 
                                            SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                            SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                            d.getName(),
                                            field.getDescribe().getName());
                }
                else {
                    // user has permission to set fieldName and it was request by the developer - so set it
                    // if the developer did not set this field and it is required, we should get an exception 
                    // when we set it here, or when we perform the actual insert.
                    cleanObj.put(field, devObj.get(field));
                }
            }
            
            try {
                // call dbInsert() to enforce sharing rules if required
                dbInsert(cleanObj);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to insert object');
            }
            return cleanObj;
        }

        /* Check to see if the user can create these objects.
         * If he can, depending on the operation mode and array operation mode do the following:
         *    operation mode:
         *      BEST_EFFORT - just set the fields that both the user can set and that were specified in the fieldsToSet.
         *      ALL_OR_NONE - if any of the fieldsToSet can't be created by the user, throw an exception.
         *    array operation mode:
         *      BEST_EFFORT - just insert the records the user can.
         *      ALL_OR_NONE - if any of the records can't be inserted, don't insert any.
         * In addition throw an exception if the user does not have the CREATE permission on the object.
         */
        public virtual SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<String> fieldsToSet) {
            if (devObjs == null || devObjs.size() == 0 || fieldsToSet == null || fieldsToSet.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.SObjectType someType = devObjs.getSObjectType();
            if(someType == null) {
                devObjs = convertToStronglyTypedList(devObjs);
                someType = devObjs.getSObjectType();
            }

            Schema.DescribeSObjectResult d = someType.getDescribe();
            if (d.isCreateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                        d.getName(),
                                                        null);
            Map<String, Schema.SObjectField> fieldMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(devObjs.getSObjectType());
            Set<String> creatableFields = fieldsToStringSet(getCreatableFields(fieldMap));
            
            /* 
              create a clean array by cloning the array, empty it, and refill the member objects by creating clean ones.
              We can't just create an array of sObjects and add the objects using devObj.getSObjectType().newSObject(); 
              because it will fail on insert. The error will be: System.TypeException: DML not allowed on abstract class SObject
            */
            sObject [] cleanObjs = devObjs.clone();
            cleanObjs.clear();
            
            // for each object in the array set only creatable fields
            for (sObject devObj: devObjs) {
                // start from a fresh sObject of same type and only set fields the user is allowed to set
                sObject cleanObj = devObj.getSObjectType().newSObject();
    
                // set all fields that were requested and the user has permission to set - throw an exception if a field was requested and user can't set and in ALL_OR_NONE mode           
                for (String fieldName : fieldsToSet) {
                    fieldName = fieldName.toLowerCase();

                    if(fieldName.endsWith('__r')) {
                        // Skip relationship objects
                        continue;
                    } 

                    if(!fieldName.endsWith('__c') && !fieldMap.containsKey(fieldName)) {
                        // This is likely a relationship field, such as OpportunityLineItem.Opportunity that exists for OpportunityLineItem.OpportunityId
                        //System.debug('Skipping : ' + fieldName);
                        continue;
                    }
                    
                    object fieldValue = devObj.get(fieldName);

                    if (fieldValue == null) {
                        // Nothing to do. We don't need to set the field to null on insert
                    } else if (creatableFields == null || creatableFields.contains(fieldName) == false) {
                        // creatableFields is either null which means no fields are allowed to be set by user, or is not null but does not contain the current fieldName
                        if (omode == OperationMode.ALL_OR_NONE)
                            // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to set fieldName
                            throw new SFDCAccessControlException('Access Violation', 
                                                SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                                SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                d.getName(),
                                                fieldName);
                    } else {
                        // user has permission to set fieldName and it was request by the developer - so set it
                        // if the developer did not set this field and it is required, we should get an exception 
                        // when we set it here, or when we perform the actual insert.
                        cleanObj.put(fieldName, fieldValue);
                    }
                }
                
                cleanObjs.add(cleanObj);
            }
            
            Database.SaveResult [] results = null;
            try {
                // call dbInsert() to enforce sharing rules if required
                results = dbInsert(cleanObjs);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to insert objects');
            }
            
            return new SFDCAccessControlResults.InsertResults(cleanObjs, results);
        }

        private List<SObject> convertToStronglyTypedList(List<sObject> devObjs) {
            Schema.SObjectType someType = devObjs.getSObjectType();

            List<sobject> stronglyTypedDevObjs = null;
            // Confirm all the sObjects in the List are of the same type.
            for(sObject so : devObjs) {
                Schema.SObjectType soType = so.getSObjectType();
                if(someType == null) {
                    someType = soType;
                    String listType = 'List<' + soType + '>';
                    stronglyTypedDevObjs = (List<SObject>)Type.forName(listType).newInstance();
                } else {
                    System.assertEquals(someType, soType, 'All sObjects must be of the same type');
                }
                stronglyTypedDevObjs.add(so);
            }
            return stronglyTypedDevObjs;
        }
        
        /* Same as insertAsUser(SObject [], List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public virtual SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<Schema.SObjectField> fieldsToSet) {
            if (devObjs == null || devObjs.size() == 0 || fieldsToSet == null || fieldsToSet.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObjs.getSObjectType().getDescribe();
            if (d.isCreateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                        d.getName(),
                                                        null);

            /* 
              create a clean array by cloning the array, empty it, and refill the member objects by creating clean ones.
              We can't just create an array of sObjects and add the objects using devObj.getSObjectType().newSObject(); 
              because it will fail on insert. The error will be: System.TypeException: DML not allowed on abstract class SObject
            */
            sObject [] cleanObjs = devObjs.clone();
            cleanObjs.clear();
            
            // for each object in the array set only creatable fields
            for (sObject devObj: devObjs) {
                // start from a fresh sObject of same type and only set fields the user is allowed to set
                sObject cleanObj = devObj.getSObjectType().newSObject();
    
                // set all fields that were requested and the user has permission to set - throw an exception if a field was requested and user can't set and in ALL_OR_NONE mode           
                for (Schema.SObjectField field : fieldsToSet) {
                    if (field.getDescribe().isCreateable() == false) {
                        // field is not allowed to be created by current user
                        if (omode == OperationMode.ALL_OR_NONE)
                            // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to set fieldName
                            throw new SFDCAccessControlException('Access Violation', 
                                                SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                                SFDCAccessControlException.ExceptionReason.NO_CREATE,
                                                d.getName(),
                                                field.getDescribe().getName());
                    }
                    else {
                        // user has permission to set fieldName and it was request by the developer - so set it
                        // if the developer did not set this field and it is required, we should get an exception 
                        // when we set it here, or when we perform the actual insert.
                        cleanObj.put(field, devObj.get(field));
                    }
                }
                
                cleanObjs.add(cleanObj);
            }
            
            Database.SaveResult [] results = null;
            try {
                // call dbInsert() to enforce sharing rules if required
                results = dbInsert(cleanObjs);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to insert objects');
            }
            
            return new SFDCAccessControlResults.InsertResults(cleanObjs, results);
        }
        
        /* Check to see if the user can update this object.
         * If he can, depending on the operation mode do the following:
         *      BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.
         *      ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception.
         * In addition throw an exception if the user does not have the UPDATE permission on the object.
         * Returns the cleanObj that was actually used to update the db.
         */
        public virtual SObject updateAsUser(SObject devObj, List<String> fieldsToUpdate) {
            if (devObj == null || fieldsToUpdate == null || fieldsToUpdate.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
            if (d.isUpdateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                        d.getName(),
                                                        null);
                                                        
            Map<String,Schema.SObjectField> fieldsMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(devObj.getSObjectType());
            
            // first load the existing object as current user (enforcing sharing based on sharing mode)
            SObject cleanObj = getObject(devObj);
            if (cleanObj == null)
                throw new SFDCAccessControlException('Record does not exist or not shared with current user', 
                                                        SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                        SFDCAccessControlException.ExceptionReason.GENERIC,
                                                        d.getName(),
                                                        null);

            Set<String> updateableFields = fieldsToStringSet(getUpdateableFields(fieldsMap));
            
            // set all fields that were requested and the user has permission to update - throw an exception if a field was requested and user can't update and in ALL_OR_NONE mode         
            for (String fieldName : fieldsToUpdate) {
                fieldName = fieldName.toLowerCase();
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
            return cleanObj;
        }
        
        /* Same as updateAsUser(SObject, List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public virtual SObject updateAsUser(SObject devObj, List<Schema.SObjectField> fieldsToUpdate) {
            if (devObj == null || fieldsToUpdate == null || fieldsToUpdate.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObj.getSObjectType().getDescribe();
            if (d.isUpdateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                        d.getName(),
                                                        null);
                                                        
            // first load the existing object as current user (enforcing sharing based on sharing mode)
            SObject cleanObj = getObject(devObj);
            if (cleanObj == null)
                throw new SFDCAccessControlException('Record does not exist or not shared with current user', 
                                                        SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                        SFDCAccessControlException.ExceptionReason.GENERIC,
                                                        d.getName(),
                                                        null);

            // set all fields that were requested and the user has permission to update - throw an exception if a field was requested and user can't update and in ALL_OR_NONE mode         
            for (Schema.SObjectField field : fieldsToUpdate) {
                if (field.getDescribe().isUpdateable() == false) {
                    // field is not allowed to be updated by current user
                    if (omode == OperationMode.ALL_OR_NONE)
                        // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to update fieldName
                        throw new SFDCAccessControlException('Access Violation', 
                                            SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                            SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                            d.getName(),
                                            field.getDescribe().getName());
                }
                else {
                    // user has permission to update fieldName and it was request by the developer - so update it
                    cleanObj.put(field, devObj.get(field));
                }
            }
            
            try {
                // call dbUpdate() to enforce sharing rules if required
                dbUpdate(cleanObj);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to update object');
            }
            return cleanObj;
        }

        /* Check to see if the user can update these objects.
         * If he can, depending on the omode and oarrmode do the following:
         *    omode:
         *      BEST_EFFORT - just set the fields that both the user can update and that were specified in the fieldsToUpdate.
         *      ALL_OR_NONE - if any of the fieldsToUpdate can't be updated by the user, throw an exception and don't update any.
         *    oarrmode
         *      BEST_EFFORT - just update the records that the user can update.
         *      ALL_OR_NONE - if any of the records can't be updated by the user, throw an exception and don't update any.
         * In addition throw an exception if the user does not have the UPDATE permission on the object. 
         */
        public virtual SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<String> fieldsToUpdate, Schema.SObjectType devType, List<String> fieldsToAlwaysUpdate) {
            if (devMap == null || devMap.size() == 0) {
                throw new AccessControlDmlException('null or empty parameter - devMap');
            }

            if (fieldsToUpdate == null || fieldsToUpdate.size() == 0) {
                throw new AccessControlDmlException('null or empty parameter - fieldsToUpdate');
            }

            // We must accepted a map argument from user instead of an array,
            // because, the user should be able to convert into map just using map.putAll(sobject_array). 
            // We can't do that because apex does not allow you to call putAll with a generic sObject value.
            // We also can't call put in a loop to add all objects, because we can't create a map with a generic
            // sobject value (in apex v16)                  
            
            //Schema.DescribeSObjectResult d = devMap.getSObjectType().getDescribe();
			Schema.DescribeSObjectResult d = devType.getDescribe();

            if (d.isUpdateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                        d.getName(),
                                                        null);
                                                        
            Map<String,Schema.SObjectField> fieldsMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(devType);
            
            // first load the existing objects as current user (enforcing sharing based on sharing mode)
            SObject [] cleanObjs = getObjects(devMap.values());
            if (cleanObjs == null || cleanObjs.size() != devMap.size())
                throw new SFDCAccessControlException('At least some record do not exist or are not shared with current user', 
                                                        SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                        SFDCAccessControlException.ExceptionReason.GENERIC,
                                                        d.getName(),
                                                        null);

            Set<String> updateableFields = fieldsToStringSet(getUpdateableFields(fieldsMap));
            
            // for each object in the array set only updateable fields
            for (sObject cleanObj: cleanObjs) {
                if (devMap.containsKey(cleanObj.id) == false)
                    throw new SFDCAccessControlException('At least some record do not exist or are not shared with current user', 
                                                            SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                            SFDCAccessControlException.ExceptionReason.GENERIC,
                                                            d.getName(),
                                                            null);

                sObject devObj = devMap.get(cleanObj.id);
                
                // set all fields that were requested and the user has permission to update - throw an exception if a field was requested and user can't update and in ALL_OR_NONE mode         
                for (String fieldName : fieldsToUpdate) {
                    fieldName = fieldName.toLowerCase();
                    if ((updateableFields == null || updateableFields.contains(fieldName) == false) && 
					    (fieldsToAlwaysUpdate == null || fieldsToAlwaysUpdate.contains(fieldName) == false) ) {
                        // updateableFields is either null which means no fields are allowed to be set by user, or is not null but does not contain the current fieldName

						Schema.SObjectField sof = fieldsMap.get(fieldName);
						Schema.DescribeFieldResult dfr = null;
						if(sof != null) {
							dfr = sof.getDescribe();
						}

						System.debug(LoggingLevel.Warn, 'The field '+d.getName()+'.[' + fieldName + '] is not updateable. ' + dfr + ' fieldsToAlwaysUpdate:' +  fieldsToAlwaysUpdate );

                        if (omode == OperationMode.ALL_OR_NONE) {
                            // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to update fieldName
                            throw new SFDCAccessControlException('Access Violation', 
                                                SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                                SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                d.getName(),
                                                fieldName);
						}
                    }
                    else {
                        // user has permission to update fieldName and it was request by the developer - so update it
                        cleanObj.put(fieldName, devObj.get(fieldName));
                    }
                }
            }
            
            Database.SaveResult [] results = null;
            try {
                // call dbUpdate() to enforce sharing rules if required
                results = dbUpdate(cleanObjs);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to update objects' + e.getMessage());
            }
            
            return new SFDCAccessControlResults.UpdateResults(cleanObjs, results);
        }
        
        /* Same as updateAsUser(Map&lt;ID, sObject&gt;, List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public virtual SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<Schema.SObjectField> fieldsToUpdate, Schema.SObjectType devType) {
            if (devMap == null || devMap.size() == 0 || fieldsToUpdate == null || fieldsToUpdate.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');

            // We must accepted a map argument from user instead of an array,
            // because, the user should be able to convert into map just using map.putAll(sobject_array). 
            // We can't do that because apex does not allow you to call putAll with a generic sObject value.
            // We also can't call put in a loop to add all objects, because we can't create a map with a generic
            // sobject value (in apex v16)                  
            
            Schema.DescribeSObjectResult d = devMap.getSObjectType().getDescribe();
            if (d.isUpdateable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                        d.getName(),
                                                        null);
                                                        
            // first load the existing objects as current user (enforcing sharing based on sharing mode)
            SObject [] cleanObjs = getObjects(devMap.values());
            if (cleanObjs == null || cleanObjs.size() != devMap.size())
                throw new SFDCAccessControlException('At least some record do not exist or are not shared with current user', 
                                                        SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                        SFDCAccessControlException.ExceptionReason.GENERIC,
                                                        d.getName(),
                                                        null);

            // for each object in the array set only updateable fields
            for (sObject cleanObj: cleanObjs) {
                if (devMap.containsKey(cleanObj.id) == false)
                    throw new SFDCAccessControlException('At least some record do not exist or are not shared with current user', 
                                                            SFDCAccessControlException.ExceptionType.NO_RECORD_FOUND, 
                                                            SFDCAccessControlException.ExceptionReason.GENERIC,
                                                            d.getName(),
                                                            null);

                sObject devObj = devMap.get(cleanObj.id);

                // set all fields that were requested and the user has permission to update - throw an exception if a field was requested and user can't update and in ALL_OR_NONE mode         
                for (Schema.SObjectField field : fieldsToUpdate) {
                    if (field.getDescribe().isUpdateable() == false) {
                        // field is not allowed to be updated by current user
                        if (omode == OperationMode.ALL_OR_NONE)
                            // if operation mode == ALL_OR_NONE - throw exception because user does not have permission to update fieldName
                            throw new SFDCAccessControlException('Access Violation', 
                                                SFDCAccessControlException.ExceptionType.FIELD_ACCESS_VIOLATION, 
                                                SFDCAccessControlException.ExceptionReason.NO_UPDATE,
                                                d.getName(),
                                                field.getDescribe().getName());
                    }
                    else {
                        // user has permission to update fieldName and it was request by the developer - so update it
                        cleanObj.put(field, devObj.get(field));
                    }
                }
            }
            
            Database.SaveResult [] results = null;
            try {
                // call dbUpdate() to enforce sharing rules if required
                results = dbUpdate(cleanObjs);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to update objects');
            }
            
            return new SFDCAccessControlResults.UpdateResults(cleanObjs, results);
        }

        /* Check to see if the user can delete this object. Throw exception if not. If he can, delete the object.
         */
        public virtual void deleteAsUser(SObject devObj) {
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

        /* Check to see if the user can delete these objects. Throw exception if not.
         *  If he can, depending on oarrmode:
         *      BEST_EFFORT - just delete the records that the user can delete.
         *      ALL_OR_NONE - if any of the records can't be deleted by the user, don't delete any.
         */
        public virtual SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] devObjs) {
            if (devObjs == null || devObjs.size() == 0)
                throw new AccessControlDmlException('null parameter');
            
            Schema.SObjectType someType = devObjs.getSObjectType();
            if(someType == null) {
                devObjs = convertToStronglyTypedList(devObjs);
                someType = devObjs.getSObjectType();
            }

            Schema.DescribeSObjectResult d = someType.getDescribe();
            if (d.isDeletable() == false) 
                throw new SFDCAccessControlException('Access Violation', 
                                                        SFDCAccessControlException.ExceptionType.OBJECT_ACCESS_VIOLATION, 
                                                        SFDCAccessControlException.ExceptionReason.NO_DELETE,
                                                        d.getName(),
                                                        null);

            Database.DeleteResult [] results = null;
            try {
                // call dbDelete() to enforce sharing rules if required
                results = dbDelete(devObjs);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to delete objects', e);
            }
            
            return new SFDCAccessControlResults.DeleteResults(results);
        }
        
        /* 
         * Check to see if the user can delete this object type.
         */
        public boolean isAuthorizedToDelete(Schema.SObjectType someType) {
            // we only need to check CRUD
            return someType.getDescribe().isDeletable();
        }
    
        /* Gets a clean object from db.
         *
         * This is private because it doesn't not respect FLS, CRUD, or sharing and is only 
         * used to get existing object to be used as a clean object before performing an updateAsUser
         *
         * Note: object names (retrieved from the describe info) should be safe to add 
         * to the SOQL as is, because they should only contain alphanumeric and under score
         */ 
        private SObject getObject(sObject obj) {
            
            String Soql = 'SELECT Id FROM ' + obj.getSObjectType().getDescribe().getName() + ' WHERE Id=\'' + String.escapeSingleQuotes(obj.Id) + '\'';
            
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
        
        /* Gets an array of clean objects from db.
         *
         * This is private because it doesn't not respect FLS, CRUD, or sharing and is only 
         * used to get existing objects to be used as a clean object before performing an updateAsUser
         *
         * Note: object names (retrieved from the describe info) should be safe to add 
         * to the SOQL as is, because they should only contain alphanumeric and under score
         */ 
        private SObject [] getObjects(sObject [] objArray) {
			//string methodName = 'SSFDCAccessController.getObjects() - ';

            System.assertNotEquals(null, objArray);
			//System.debug(methodName + 'objArray.getSObjectType(): ' + objArray.getSObjectType() + ' objArray: ' + objArray);
			//System.debug(methodName + 'objArray.getSObjectType().getDescribe(): ' + objArray.getSObjectType().getDescribe());
            String Soql = 'SELECT Id FROM ' + objArray.getSObjectType().getDescribe().getName() + ' WHERE ';
            Boolean emptyIds = true;
            
            // add all Ids
            for (SObject obj : objArray) {
                if (emptyIds == false)
                    Soql += ' or ';
                else
                    emptyIds = false;
                
                Soql += 'ID=\'' + String.escapeSingleQuotes(obj.Id) + '\'';
            }
            
            List<SObject> res;
            
            try {
                // call dbQuery() to enforce sharing rules if required
                res = dbQuery(Soql);
            } catch (Exception e) {
                throw new AccessControlDmlException('Failed to query object');
            }
            
            return res;
        }
    }
}
