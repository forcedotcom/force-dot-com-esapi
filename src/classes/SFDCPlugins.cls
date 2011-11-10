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
 * @created 2011
 */
 
/**
 * This class contains plugins for use in the ESAPI.
 * The DescribeInfoCache plugin provides caching functionality for describe info.
 */
public with sharing class SFDCPlugins {
	public static SFDCIDescribeInfoCache SFDC_DescribeInfoCache = new SFDCDefaultDescribeInfoCache();
	
    /**
     * This interface defines the methods for a describe info cache implementation.
     */
	public interface SFDCIDescribeInfoCache {
        /**
         *  Returns a field map for a given sobject type. 
         *
         *  @param objectType sobject type for ex. Contact.getSObjectType()
         *  @returns FieldMap [Key:FieldName,Value:Schema.SObjectField]
         */
		Map<String, Schema.SObjectField> fieldMapFor(Schema.SObjectType objectType);
	}

    /**
     *  Register your own function to handle the describe cache. 
     *
     *  @param impl an object of your SFDCIDescribeInfoCache implementation 
     */
	public static void registerDescribeInfoCache(SFDCIDescribeInfoCache impl){
		SFDC_DescribeInfoCache = impl;
	}

	/**
	 * Default implementation for describe caching. You can use your existing cache by 
	 * implementing the SFDCIDescribeInfoCache interface and registering it with the ESAPI 
	 * library by calling registerDescribeInfoCache().
	 */
	public virtual class SFDCDefaultDescribeInfoCache implements SFDCIDescribeInfoCache {
        // Key : SobjectAPIName  For ex. Account 
        // Value : Map<String, Schema.SObjectField>, field map (k:fieldname, v:Schema.Sobjectfield)
        final Map<String, Map<String, Schema.SObjectField>> FIELD_CACHE = new Map<String, Map<String, Schema.SObjectField>>();

        /**
         *  Returns a field map for a given sobject type. 
         *
         *  Note : this method is kept public for Test cases to share the same field map info, without requiring a field desribe.
         *
         *  @param objectType sobject type for ex. Contact.getSObjectType()
         *  @returns FieldMap [Key:FieldName,Value:Schema.SObjectField]
         */
        public virtual Map<String, Schema.SObjectField> fieldMapFor(Schema.SObjectType objectType) {
            Map<String, Schema.SObjectField> fieldMap = null;
            Schema.DescribeSObjectResult d = objectType.getDescribe(); // added since we use this more than once
            String sobjName = d.getName();
            //String normalizedObjectType = sobjName.toLowerCase(); // not needed    
            if (FIELD_CACHE.containsKey(sobjName)) {
                fieldMap = FIELD_CACHE.get(sobjName);
            } else {
                fieldMap = d.fields.getMap();
                // cache it for next use
                FIELD_CACHE.put(sobjName, fieldMap);
            }
    
            return fieldMap;
        }
        
	}
}