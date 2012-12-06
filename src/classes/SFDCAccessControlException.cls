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
 * This class provides access control exception functionality. You might not want to expose the details of the exception to the users.
 * Note : to avoid XSS, make sure to escape text before presenting it to the user. 
 */
global with sharing class SFDCAccessControlException extends Exception {

	/**
	 * ExceptionType - this enum defines the different types of access control exceptions.
	 */
	global enum ExceptionType {
		/**
		 * This error is a generic error type.
		 */
		GENERIC,
		/**
		 * This error type is an object level access violation.
		 */
		OBJECT_ACCESS_VIOLATION,
		/**
		 * This error type is a field level access violation.
		 */
		FIELD_ACCESS_VIOLATION, 
		/**
		 * This error type is a sharing access violation.
		 */
		SHARING_ACCESS_VIOLATION, 
		/**
		 * This error type is a generic record not found error. This can be due to record does not exist, sharing violation, or other errors. 
		 */
		NO_RECORD_FOUND,
		/**
		 * This error type is a generic field not found error. 
		 */
		FIELD_NOT_FOUND}

	/**
	 * ExceptionReason - this enum defines the different reasons for the exception type.
	 */
	global enum ExceptionReason {
		/**
		 * This is a generic reason.
		 */
		GENERIC, 
		/**
		 * This error is due to the user not having the create permission on the specific object/field/record.
		 */
		NO_CREATE, 
		/**
		 * This error is due to the user not having the read permission on the specific object/field/record.
		 */
		NO_READ, 
		/**
		 * This error is due to the user not having the update permission on the specific object/field/record.
		 */
		NO_UPDATE, 
		/**
		 * This error is due to the user not having the delete permission on the specific object/field/record.
		 */
		NO_DELETE}
	
	private ExceptionType eType;
	private ExceptionReason eReason;
	private String eObject;
	private String eField;
	private String eText;

	/**
	 * Constructor for SFDCAccessControlException.
	 * @param eText Error text
	 * @param eType ExceptionType for this error
	 * @param eReason ExceptionReason for this error
	 * @param eObject The object name this error was triggered on
	 * @param eField The field name this error was triggered on
	 */
	global SFDCAccessControlException(String eText, ExceptionType eType, ExceptionReason eReason, String eObject, String eField) {
		this.eText = eText;
		this.eType = eType;
		this.eReason = eReason;
		this.eObject = eObject;
		this.eField = eField;
	}

	/**
 	 * Get the exception type - Object Access Violation, Field Access Violation, etc.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global ExceptionType getExceptionType() {
		return this.eType;
	}

	/**
	 * Get the exception reason - no create, no update, etc.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global ExceptionReason getExceptionReason() {
		return this.eReason;
	}

	/**
	 * Get the object on which the exception occurred.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getExceptionObject() {
		return this.eObject;
	}
	
	/**
	 * Get the field on which the exception occurred.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getExceptionField() {
		return this.eField;
	}
	
	/**
	 * Get the error text.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getText() {
		return this.eText;
	}

    /**
     * Override the getMessage method to avoid getting only script-thrown exception as the exception message
     * Note : to avoid XSS, make sure to escape text before presenting it to the user.
     */ 
    global override String getMessage() {
        return this.eText;
    }

}