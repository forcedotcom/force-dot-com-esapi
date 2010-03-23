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
 * This class is a basic encoder/escaper to help prevent some XSS attacks etc.  
 */
global with sharing class SFDCEncoder {
	
	/* TODO Yoel - all these functions should be converted into a white list aproach - I am using blacklist to be consistent with the VISUALFORCE functions */ 
	/* TODO Yoel - Do we need to encode ASCII/Unicode white-space/new-line characters? These used to cause some security issues in some browsers not sure if this is still the case */
	 	
	/* Note - the order of these encoding strings is very important so we don't end up with double encoding. 
	      Each string we search for, must not be found as a result of a previous encoded string replacement */
	 	
	private static final String[] HTML_DECODED  = new String[]{ '&', '<', '>', '"', '\''};
	private static final String[] HTML_ENCODED  = new String[]{ '&amp;', '&lt;', '&gt;', '&quot;', '&#39;' };
	
    private static final String[] JS_DECODED = new String[] { '\\', '\'', '\n', '\r', '"', '!--', '/', '<', '>' };
    private static final String[] JS_ENCODED = new String[] { '\\\\', '\\\'', '\\n', '\\r', '\\"', '\\!--', '\\/', '\\u003C', '\\u003E' };
    
	private static final String[] JSINHTML_DECODED = new String[] { '&', '\\', '\'', '"', '\r', '\n', '<', '>' };
	private static final String[] JSINHTML_ENCODED = new String[] { '&amp;', '\\\\', '\\\'', '\\&quot;', '\\r', '\\n', '&lt;', '&gt;' };

	// similar to the VisualForce HTMLENCODE function
	global String SFDC_HTMLENCODE(String input) {
		return ENCODE(input, HTML_DECODED, HTML_ENCODED);
	}

	// similar to the VisualForce JSENCODE function
	global String SFDC_JSENCODE(String input) {
		return ENCODE(input, JS_DECODED, JS_ENCODED);
	}

	// similar to the VisualForce JSINHTMLENCODE function
	global String SFDC_JSINHTMLENCODE(String input) {
		return ENCODE(input, JSINHTML_DECODED, JSINHTML_ENCODED);
	}

	/* Note : this function always encodes into UTF-8 URL encoding - if you need another enocoding type, use the second function which allows to set the encoding */
	global String SFDC_URLENCODE(String input) {
		return EncodingUtil.urlEncode(input, 'UTF-8');
	}
	
	global String SFDC_URLENCODE(String input, String encoding) {
		return EncodingUtil.urlEncode(input, encoding);
	}

	private String ENCODE(String input, String[] fromArr, String[] toArr) {
		if (input == null || input.length() == 0)
			return input;

		for (Integer i = 0; i < fromArr.size(); ++i) {
			input = input.replace(fromArr[i], toArr[i]);
		}
		
		return input;
	}
}