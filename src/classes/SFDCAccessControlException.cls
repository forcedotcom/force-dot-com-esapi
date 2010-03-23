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
global with sharing class SFDCAccessControlException extends SFDCValidationException {
	
	global enum ExceptionType {GENERIC, OBJECT_ACCESS_VIOLATION, FIELD_ACCESS_VIOLATION, SHARING_ACCESS_VIOLATION, NO_RECORD_FOUND}
	global enum ExceptionReason {GENERIC, NO_CREATE, NO_READ, NO_UPDATE, NO_DELETE}
	
	private ExceptionType eType;
	private ExceptionReason eReason;
	private String eObject;
	private String eField;
	private String eText;

	global SFDCAccessControlException(String eText, ExceptionType eType, ExceptionReason eReason, String eObject, String eField) {
		this.eText = eText;
		this.eType = eType;
		this.eReason = eReason;
		this.eObject = eObject;
		this.eField = eField;
	}

	/*
 	 * Get the exception type - Object Access Violation, Field Access Vilation, etc.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global ExceptionType getExceptionType() {
		return this.eType;
	}

	/*
	 * Get the exception reason - no create, no update, etc.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global ExceptionReason getExceptionReason() {
		return this.eReason;
	}

	/*
	 * Get the object on which the exception occurred.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getExceptionObject() {
		return this.eObject;
	}
	
	/*
	 * Get the field on which the exception occurred.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getExceptionField() {
		return this.eField;
	}
	
	/*
	 * Get the error text.
 	 * You might not want to expose the details of the exception to the users.
	 * Note : to avoid XSS, make sure to escape text before presenting it to the user.
	 */ 
	global String getText() {
		return this.eText;
	}
}