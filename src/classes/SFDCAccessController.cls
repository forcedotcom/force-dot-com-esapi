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
        INHERIT}

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
    }
    
    private without sharing class AccessControllerWithoutSharing extends AccessControllerInternal {
        private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
    }
    
    private class AccessControllerInheritSharing extends AccessControllerInternal{
        private override List<SObject> dbQuery(String query) { return Database.query(query); }
        private override void dbInsert(sObject obj) { insert obj; }
        private override Database.SaveResult[] dbInsert(sObject [] objs) { return Database.insert(objs, arrayAllOrNoneParam); }
        private override void dbUpdate(sObject obj) { update obj; }
        private override Database.SaveResult[] dbUpdate(sObject [] objs) { return Database.update(objs, arrayAllOrNoneParam); }
        private override void dbDelete(sObject obj) { delete obj; }
        private override Database.DeleteResult[] dbDelete(sObject [] objs) { return Database.delete(objs, arrayAllOrNoneParam); }
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
        SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<String> fieldsToUpdate);
        SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> objMap, List<Schema.SObjectField> fieldsToUpdate);
        
        void deleteAsUser(SObject someObj);
        SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] someObjs);
        
        List<Schema.SObjectField> getViewableFields(SObjectType someType);
        List<Schema.SObjectField> getUpdateableFields(SObjectType someType);
        List<Schema.SObjectField> getCreatableFields(SObjectType someType);
        
        boolean isAuthorizedToView(Schema.SObjectType someType, List<String> fieldNames);
        boolean isAuthorizedToCreate(Schema.SObjectType someType, List<String> fieldNames);
        boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fieldNames);
        
        boolean isAuthorizedToView(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        boolean isAuthorizedToCreate(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields);
        
        boolean isAuthorizedToDelete(Schema.SObjectType someType);
    }
    
    /* instance variables */
    private AccessControllerWithSharing acws; // sharing access control object that was created with sharing
    private AccessControllerWithoutSharing acwos; // sharing access control object that was created without sharing
    private AccessControllerInheritSharing acis; // sharing access control object that was created with sharing inherited from caller
    private SharingMode smode; // the current sharing mode of this instance. We will call the proper instance from the above three based on this value.
    
    /**
     * Default constructor - will set sharing mode to SharingMode.WITH, operation mode to OperationMode.ALL_OR_NONE, 
     *  and array operation mode to OperationMode.ALL_OR_NONE.
     */
    global SFDCAccessController() {
        // init the three access contorl instances to enforce sharing
        acws = new AccessControllerWithSharing();
        acwos = new AccessControllerWithoutSharing();
        acis = new AccessControllerInheritSharing();
        
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
        if (smode == SharingMode.WITH)
            return acws;
        else if (smode == SharingMode.WITHOUT)
            return acwos;
        else // we always enforce smode to be a valid value - so no need to check it here again if null or incorrect value
            return acis;
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
            
        if (smode == SharingMode.WITH || smode == SharingMode.WITHOUT || smode == SharingMode.INHERIT)
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
        acws.setOperationMode(omode);
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
         * Note : sharing mode is set in the outter class, but this is set on the actual instance objects 
         *  because that is where this mode is going to be used)
         */
        acws.setArrayOperationMode(oarrmode);
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
        // call updateAsUser using specific instance based on current sharing mode
        return getACImpl().updateAsUser(objMap, fieldsToUpdate);
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
        return getACImpl().updateAsUser(objMap, fieldsToUpdate);
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
       
        public boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
            // check at object-level first
            if (!someType.getDescribe().isUpdateable()){
                return false;
            }
            
            // check each field
            for (Schema.SObjectField f : fields) {
                if (!f.getDescribe().isUpdateable()){
                    return false;
                }
            }
            return true;
        }
        
        public boolean isAuthorizedToUpdate(Schema.SObjectType someType, List<String> fieldNames) {
            Schema.DescribeSObjectResult objDesc = someType.getDescribe();
            if(!objDesc.isUpdateable()){
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
                    return false;
                }
            }
            return true;
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
            Schema.DescribeSObjectResult objDesc = someType.getDescribe();
            if (!objDesc.isCreateable()){
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
                if (!sObjectFld.getDescribe().isCreateable()){
                    return false;
                }
            }
            return true;
        }
        
        public boolean isAuthorizedToCreate(Schema.SObjectType someType, List<Schema.SObjectField> fields) {
            // check at object-level first
            if (!someType.getDescribe().isCreateable()){
                return false;
            }
            
            // check each field
            for (Schema.SObjectField f : fields) {
                if (!f.getDescribe().isCreateable()){
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
        public SObject insertAsUser(SObject devObj, List<String> fieldsToSet) {
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
        public SObject insertAsUser(SObject devObj, List<Schema.SObjectField> fieldsToSet) {
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
        public SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<String> fieldsToSet) {
            if (devObjs == null || devObjs.size() == 0 || fieldsToSet == null || fieldsToSet.size() == 0)
                throw new AccessControlDmlException('null or empty parameter');
            
            Schema.DescribeSObjectResult d = devObjs.getSObjectType().getDescribe();
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
        
        /* Same as insertAsUser(SObject [], List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public SFDCAccessControlResults.InsertResults insertAsUser(SObject [] devObjs, List<Schema.SObjectField> fieldsToSet) {
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
        public SObject updateAsUser(SObject devObj, List<String> fieldsToUpdate) {
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
        public SObject updateAsUser(SObject devObj, List<Schema.SObjectField> fieldsToUpdate) {
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
        public SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<String> fieldsToUpdate) {
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
                                                        
            Map<String,Schema.SObjectField> fieldsMap = SFDCPlugins.SFDC_DescribeInfoCache.fieldMapFor(devMap.getSObjectType());
            
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
        
        /* Same as updateAsUser(Map&lt;ID, sObject&gt;, List&lt;String&gt;) but with Schema.SObjectField instead of string.
         */
        public SFDCAccessControlResults.UpdateResults updateAsUser(Map<ID, sObject> devMap, List<Schema.SObjectField> fieldsToUpdate) {
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

        /* Check to see if the user can delete these objects. Throw exception if not.
         *  If he can, depending on oarrmode:
         *      BEST_EFFORT - just delete the records that the user can delete.
         *      ALL_OR_NONE - if any of the records can't be deleted by the user, don't delete any.
         */
        public SFDCAccessControlResults.DeleteResults deleteAsUser(SObject [] devObjs) {
            if (devObjs == null || devObjs.size() == 0)
                throw new AccessControlDmlException('null parameter');
            
            Schema.DescribeSObjectResult d = devObjs.getSObjectType().getDescribe();
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
                throw new AccessControlDmlException('Failed to delete objects');
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