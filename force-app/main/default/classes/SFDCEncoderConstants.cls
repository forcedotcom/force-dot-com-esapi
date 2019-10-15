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
 * Common character classes used for input validation, output encoding, verifying password strength
 * CSRF token generation, generating salts, etc. I removed all the constatnts that are not used so we
 * don't burn governor limits.
 */
public with sharing class SFDCEncoderConstants {

	private SFDCEncoderConstants() {
		// prevent instantiation
	}

	/**
	 * 0-9
	 */
	public static final String[] CHAR_DIGITS = new String[]{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	public static final Set<Integer> DIGITS;
	static {
		DIGITS = SFDCStringUtils.stringArrayToIntegerSet(CHAR_DIGITS);
	}

	/**
	 * 
	 */
	public static final String[] VALID_FILE_EXTENSIONS = new String[]{ '.zip', '.pdf', '.txt', '.html', '.xml', '.jpg', '.jpeg', '.png', '.gif', '.bmp'};
}