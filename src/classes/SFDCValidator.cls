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
 * This class provides basic validation functionality for different types of input. <br>
 * Note : we don't do any decoding before the checks because that really depends on the context used.
 *   Instead, we enforce strict input validation on the input as is. <br>
 * Note : we expose almost every function in this class in two forms isValid and getValid. They work 
 *   the same way internally. The only difference is that, the isValid will call the getValid internally, 
 *   catch any exceptions, and return false in that case. So you can use which ever you prefer, it is
 *   only a style preference. the GetValid will always return the exact string as the input. 
 */
global with sharing class SFDCValidator {

	/**
	 * This is a basic SFDCValidationException class. It does not add any functionality to the generic Exception class.
	 * However, in Apex we must extend the Exception class before using it. 
	 */
	global with sharing virtual class SFDCValidationException extends Exception {
	}

	/**
	 * Calls getValidCreditCard and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidCreditCard(unsafe_text, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidCreditCard(String input, Boolean allowNull) {
		try {
			getValidCreditCard(input, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns the exact original input if all tests passed. Invalid input
	 * will generate an exception. This function will only validate Visa and MasterCard 16 digits credit cards. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     creditcard = ESAPI.validator().getValidCreditCard(unsafe_text, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
	 * 
	 * @return Original input
	 * 
	 * @throws Exception
	 */
	global String getValidCreditCard(String input, Boolean allowNull) {
		SFDCCreditCardValidationRule ccvr = new SFDCCreditCardValidationRule('creditcard');
		ccvr.setAllowNull(allowNull);
		ccvr.assertValid(input);
		return input;
	}
	
	/**
	 * Calls SFDC_getValidDate and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidDate(unsafe_text, SFDCPatterns.Date1, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidDate(String input, String format, Boolean allowNull) {
		try {
			SFDC_getValidDate(input, format, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Returns the original input if it is a valid date. Invalid input will generate a descriptive exception.
	 * Uses RegEx patterns because Apex does not allow the user to choose which format he is going to use when setting the date/datetime objects. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     datestr = ESAPI.validator().SFDC_getValidDate(unsafe_text, SFDCPatterns.Date1, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param format 
	 * 		Required formatting of date inputed (In RegEx - some basic patterns can be found in the SFDCPatterns class).
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
	 * 
	 * @return Original input
	 * 
	 * @throws Exception
	 */
	global String SFDC_getValidDate(String input, String format, Boolean allowNull) {

		SFDCStringValidationRule svr;
		
	    try {
	    	svr = new SFDCStringValidationRule( 'Date', format);
	    } catch (Exception e) {
	    	// format seems to be invalid
	    	throw new SFDCValidationException('Invalid date format');
	    }

		svr.setAllowNull(allowNull);
		svr.setMaximumLength(30);
		
	    try {
	    	svr.assertValid(input);
	    } catch (Exception e) {
	    	// Date did not match the regex pattern or other basic string rule checks
	    	throw new SFDCValidationException('Invalid date input');
	    }
		
		return input;
	}

	/**
	 * Calls getValidDouble and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidDouble(unsafe_text, 1.0, 2.0, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidDouble(String input, Double minValue, Double maxValue, Boolean allowNull) {
        try {
            getValidDouble(input, minValue, maxValue, allowNull);
            return true;
        } catch( Exception e ) {
            return false;
        }
	}

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate an exception. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     Double dblValue = ESAPI.validator().getValidDouble(unsafe_text, 1.0, 2.0, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated real number as a double.
     * 
     * @throws Exception
	 */
	global Double getValidDouble(String input, Double minValue, Double maxValue, Boolean allowNull) {
		SFDCNumberValidationRule nvr = new SFDCNumberValidationRule( 'number', minValue, maxValue );
		nvr.setAllowNull(allowNull);
		return nvr.getValid(input);
	}
	
	/**
	 * Calls getValidInteger and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidInteger(unsafe_text, 1, 5, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidInteger(String input, Integer minValue, Integer maxValue, Boolean allowNull) {
		try {
			getValidInteger(input, minValue, maxValue, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a validated integer. Invalid input
	 * will generate an exception. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     Integer intValue = ESAPI.validator().getValidInteger(unsafe_text, 1, 5, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated number as an integer.
     * 
     * @throws Exception
	 */
	global Integer getValidInteger(String input, Integer minValue, Integer maxValue, Boolean allowNull) {
		SFDCIntegerValidationRule ivr = new SFDCIntegerValidationRule( 'number', minValue, maxValue );
		ivr.setAllowNull(allowNull);
		return ivr.getValid(input);
	}
	
	/**
	 * Calls getValidNumber and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidNumber(unsafe_text, 0, 5000000, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidNumber(String input, Long minValue, Long maxValue, Boolean allowNull) {
		try {
			getValidNumber(input, minValue, maxValue, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a validated number as a double within the range of minValue to maxValue. Invalid input
	 * will generate an exception. (This function accepts minValue and maxValue as Long vs. Double in the getValidDouble) <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     Double dblValue = ESAPI.validator().getValidNumber(unsafe_text, 0, 5000000, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated number as a double.
     * 
     * @throws Exception
	 */
	global Double getValidNumber(String input, Long minValue, Long maxValue, Boolean allowNull) {
		return getValidDouble(input, minValue, maxValue, allowNull);
	}
	
	/**
	 * Calls getValidListItem and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidListItem(unsafe_text, new Set&lt;String&gt;{'US', 'CANADA'}) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidListItem(String input, Set<String> validItems) {
		try {
			getValidListItem(input, validItems);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Confirm that the input is in the validItems list. Invalid or non-matching input
	 * will generate an exception. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     listItemStr = ESAPI.validator().getValidListItem(unsafe_text, new Set&lt;String&gt;{'US', 'CANADA'});
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param input 
	 * 		The value to search 'validItems' for.
	 * @param validItems 
	 * 		The list of valid items to search for 'input' in.
	 * 
	 * @return The input String if matches to one of the items in the validItems list.
	 * 
	 * @throws Exception
	 */
	global String getValidListItem(String input, Set<String> validItems) {
		if (validItems.contains(input))
			return input;		
		throw new SFDCValidationException('Invalid list item');
	}
	
	/**
	 * Calls getValidFileContent and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidFileContent(unsafe_text, 255, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidFileContent(String input, Integer maxBytes, Boolean allowNull) {
		try {
			getValidFileContent(input, maxBytes, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Returns the validated file content as a String. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
	 * will generate an exception. The default implementation only checks max size, and null. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     fileContentStr = ESAPI.validator().getValidFileContent(unsafe_text, 255, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param input 
	 * 		The actual input data to validate.
	 * @param maxBytes 
	 * 		The maximum number of bytes allowed in a legal file.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
	 * 
	 * @return A String containing valid file content.
	 * 
	 * @throws Exception
	 */
	global String getValidFileContent(String input, Integer maxBytes, Boolean allowNull) {
		if (SFDCStringUtils.isEmpty(input)) {
			if (allowNull)
				return null;
   			throw new SFDCValidationException('Input required');
		}
		
		if (input.length() > maxBytes )
			throw new SFDCValidationException('Invalid file content can not exceed ' + maxBytes + ' bytes');
		
		return input;
	}
	
	/**
	 * Calls getValidPrintable and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidPrintable(unsafe_text, 255, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidPrintable(String input, Integer maxLength, Boolean allowNull) {
		try {
			getValidPrintable(input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns the input after validating it contain only printable characters. Invalid input will generate an exception. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     printableStr = ESAPI.validator().getValidPrintable(unsafe_text, 255, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 *  @param input 
	 *  		data to be verified as printable characters
	 *  @param maxLength 
	 *  		Maximum number of bytes allowed in 'input'
	 *  @param allowNull 
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
	 *  
	 *  @return The input string verified to contain only printable characters
	 *  
	 *  @throws Exception
	 */
	global String getValidPrintable(String input, Integer maxLength, Boolean allowNull) {
		
		if (SFDCStringUtils.isEmpty(input)) {
			if (allowNull)
				return null;
   			throw new SFDCValidationException('Input bytes required');
		}

		if (input.length() > maxLength) {
			throw new SFDCValidationException('Input bytes can not exceed ' + maxLength + ' bytes');
		}

		// loop through the string and check each byte
		Integer c;
    	for (Integer i = 0; i < input.length(); i++) {
    		try {
        		c = SFDCCharacter.toInt(input.substring(i, i + 1));
    		} catch (Exception e) {
    			throw new SFDCValidationException('Invalid non-ASCII input bytes');
    		}
        	if (c < 32 || c > 126) {
        		throw new SFDCValidationException('Invalid non-ASCII input bytes');
        	}
    	}
		
		return input;
	}
	
	/**
	 * Calls SFDC_getValidFileName with the default list of allowedExtensions. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidFileName(unsafe_text, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidFileName(String input, Boolean allowNull) {
		return SFDC_isValidFileName(input, SFDCEncoderConstants.VALID_FILE_EXTENSIONS, allowNull);
	}
	
	/**
	 * Calls SFDC_getValidFileName and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidFileName(unsafe_text, new List&lt;String&gt;{'.png', '.jpg', '.bmp'}, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidFileName(String input, List<String> allowedExtensions, Boolean allowNull) {
		try {
			SFDC_getValidFileName(input, allowedExtensions, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Calls SFDC_getValidFileName with the default list of allowedExtensions. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     fileNameStr = ESAPI.validator().SFDC_getValidFileName(unsafe_text, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 */
	global String SFDC_getValidFileName(String input, Boolean allowNull) {
		return SFDC_getValidFileName(input, SFDCEncoderConstants.VALID_FILE_EXTENSIONS, allowNull);
	}
	
	/**
	 * Returns the input string after validating it as a valid file name. Implementors should check for allowed file extensions here, as well as allowed file name characters. Invalid input
	 * will generate an exception. Apex does not have a File object so we could not use it to verify the canonical file name. Instead we just used a RegEx pattern. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     fileNameStr = ESAPI.validator().SFDC_getValidFileName(unsafe_text, new List&lt;String&gt;{'.png', '.jpg', '.bmp'}, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE> 
	 * 
     * @param input 
     * 		The actual input data to validate.
     * @param allowedExtensions 
     * 		The extensions you want to allow for the input file name. This is case insensitive.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
     * 
     * @return Input after validating it to be a valid file name
     * 
     * @throws Exception
	 */
	global String SFDC_getValidFileName(String input, List<String> allowedExtensions, Boolean allowNull) {
		if (SFDCStringUtils.isEmpty(input)) {
			if (allowNull)
				return null;
   			throw new SFDCValidationException('Input file name required');
		}
		
		// do basic validation using RegEx
		SFDCStringValidationRule svr = new SFDCStringValidationRule('filename');
		try {
			svr.addWhitelistPattern(SFDCPatterns.FileName);
		} catch (Exception e) {
	    	// format seems to be invalid
	    	throw new SFDCValidationException('Invalid file name format');
		}
		svr.setMaximumLength(255);
		svr.setAllowNull(allowNull);
		try {
			svr.assertValid(input);
		} catch (Exception e) {
	    	throw new SFDCValidationException('Invalid file name input');
		}

		// verify extensions
		for (Integer i = 0; i < allowedExtensions.size(); ++i) {
			// check if the input file name ends with one of the allowed file extensions. However, make sure we only compare it to non empty file extensions 
			if (SFDCStringUtils.isEmpty(allowedExtensions[i]) == false && 
					input.toLowerCase().endsWith(allowedExtensions[i].toLowerCase())) {
				return input;
			}
		}
		throw new SFDCValidationException('Invalid file name does not have valid extension');
	}
	
	/**
	 * Calls SFDC_assertValidFileUpload using the default allowed file extensions and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidFileUpload(unsafe_fileName, unsafe_fileContent, 255, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidFileUpload(String filename, String content, Integer maxBytes, Boolean allowNull) {
		try {
			SFDC_assertValidFileUpload(filename, content, maxBytes, SFDCEncoderConstants.VALID_FILE_EXTENSIONS, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Validates the filename, and content of a file. Invalid input
	 * will generate an exception. Does not check file path because Force.com does not have the notion of a file path.
	 * This function internally just calls the SFDC_getValidFileName() and getValidFileContent() functions. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     ESAPI.validator().SFDC_assertValidFileUpload(unsafe_fileName, unsafe_fileContent, 255,
	 *         new List&lt;String&gt;{'.png', '.jpg', '.bmp'}, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param filename 
	 * 		The filename of the uploaded file
	 * @param content 
	 * 		A String containing the content of the uploaded file.
	 * @param maxBytes 
	 * 		The max number of bytes allowed for a legal file upload.
	 * @param allowedExtensions 
	 * 		The list of allowed extensions.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw an exception.
	 * 
	 * @throws Exception
	 */
	global void SFDC_assertValidFileUpload(String filename, String content, Integer maxBytes, List<String> allowedExtensions, Boolean allowNull) {
		SFDC_getValidFileName(filename, allowedExtensions, allowNull);
		getValidFileContent(content, maxBytes, allowNull);
	}
	
	/**
	 * Calls assertValidHTTPRequestParameterSet and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().isValidHTTPRequestParameterSet(pageReference, 
	 *         new Set&lt;String&gt;{'USER', 'PASSWORD'}, 
	 *         new Set&lt;String&gt;{'GROUP', 'LANG'},
	 *         255, false) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean isValidHTTPRequestParameterSet(PageReference request, Set<String> required, Set<String> optional) {
		try {
			assertValidHTTPRequestParameterSet(request, required, optional);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Validates that the parameters in the current (PagReference) request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate an exception. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     ESAPI.validator().assertValidHTTPRequestParameterSet(pageReference, 
	 *         new Set&lt;String&gt;{'USER', 'PASSWORD'}, 
	 *         new Set&lt;String&gt;{'GROUP', 'LANG'},
	 *         255, false);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 * @param request 
	 * 		A PageReference request object to validate
	 * @param required 
	 * 		parameters that are required to be in HTTP request
	 * @param optional 
	 * 		additional parameters that may be in an HTTP request
	 * 
	 * @throws exception
	 */
	global void assertValidHTTPRequestParameterSet(PageReference request, Set<String> required, Set<String> optional) {
		
		if (request == null || required == null || optional == null)
   			throw new SFDCValidationException('null parameter');
		
		Set<String> actualNames = request.getParameters().keySet();
		
		// verify ALL required parameters are present
		Set<String> missing = new Set<String>(required);
		missing.removeAll(actualNames);
		if (missing.size() > 0)
			throw new SFDCValidationException('Invalid HTTP request missing parameters');
		
		// verify ONLY optional + required parameters are present
		Set<String> extra = new Set<String>(actualNames);
		extra.removeAll(required);
		extra.removeAll(optional);
		if (extra.size() > 0) {
			throw new SFDCValidationException('Invalid HTTP request extra parameters');
		}
	}

	/**
	 * Calls SFDC_getValidRedirectLocation and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidRedirectLocation(unsafe_text, 'www.mydomain.com') == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidRedirectLocation(String input, String currentDomain) {
		
		try {
			SFDC_getValidRedirectLocation(input, currentDomain);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Calls SFDC_getValidRedirectLocation and returns true if no exceptions are thrown. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * if (ESAPI.validator().SFDC_isValidRedirectLocation(unsafe_text) == false)
	 *     // error handling
	 * </PRE>
	 */
	global Boolean SFDC_isValidRedirectLocation(String input) {
		
		try {
			SFDC_getValidRedirectLocation(input);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Calls SFDC_getValidRedirectLocation while trying to get the current domain from ApexPages.currentPage(). <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     redirectStr = ESAPI.validator().SFDC_getValidRedirectLocation(unsafe_text);
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 */
	global String SFDC_getValidRedirectLocation(String input) {
		
		// in this function the user did not provide us the current domain. Try to retrieve it from ApexPage.currentPage() if we fail set it to null
		String currentDomain = null;
		
		try {
			currentDomain = ApexPages.currentPage().getHeaders().get('Host');

			if (currentDomain != null)
				currentDomain = currentDomain.trim();
			
			if (SFDCStringUtils.isEmpty(currentDomain))
				currentDomain = null;
				
		} catch (Exception e) {
			currentDomain = null;
		}

		return SFDC_getValidRedirectLocation(input, currentDomain);
	}
	
	/**
	 * Returns the input string after validating it is a valid redirect location string. Invalid input will generate an exception.
	 * The default validation only allows redirects to *.salesforce.com, current domain, and relative URLs.
	 * It also makes sure the URLs only allows http:// and https:// and is no longer than 512 characters long. <br><br>
	 * 
	 * Note : this implementation does not protect against directory traversal. <br><br>
	 * 
	 * Example:<br>
	 * <PRE>
	 * try {
	 *     redirectStr = ESAPI.validator().SFDC_getValidRedirectLocation(unsafe_text, 'www.mydomain.com');
	 * } catch () {
	 *     // error handling
	 * }
	 * </PRE>
	 * 
	 *  @param input 
	 *  		redirect location to be validated
	 *  @param currentDomain 
	 *  		currentDomain to be used. (You should only use this if using ApexPages.CurrentPage() does not work for you) If null, will only allow relative URLS and *.salesforce.com domains. 
	 *  
	 *  @return The input string after validating it is a valid redirect location
	 *  
	 *  @throws Exception
	 */
	global String SFDC_getValidRedirectLocation(String input, String currentDomain) {
		
		String tmp;
		Integer startPos = 0;
		Integer endPos = 0;
		Boolean allowEmptyURI = false;
		
		if (SFDCStringUtils.isEmpty(input))
			throw new SFDCValidationException('Input URL required');
			
		if (input.length() > 512)
			throw new SFDCValidationException('Input URL must not exceed 512 characters');
			
		// check if starts with http:// or https://
		if (input.toLowerCase().startsWith('http://')) {
			// remove http:// by setting startPos to after it
			startPos = 7;
		} else if (input.toLowerCase().startsWith('https://')) {
			// remove https:// by setting startPos to after it
			startPos = 8;
		} else if (input.startsWith('/') == false) {
			throw new SFDCValidationException('Invalid input URL');
		}
		
		if (startPos > 0) {
			// check domain
			
			// search for next / which will signal end of domain
			endPos = input.indexOf('/', startPos);
			if (endPos == -1) {
				// did not find / to signal end of domain, check entire remainder as domain 
				endPos = input.length();
			}
			
			// check domain - allow only strict domain name characters
			tmp = input.substring(startPos, endPos);
			
			// restrict domain to 100 characters (officialy domains are allowed to have up to 255 characters after setting it into DNS packet format. So in the regular string representation it must be up to 253 - See RFC 1034 Sec 3.1)
			
			if (SFDCStringUtils.isEmpty(tmp))
				throw new SFDCValidationException('Input domain required in URL');
				
			if (tmp.length() > 100)
				throw new SFDCValidationException('Input domain in URL must not exceed 100 characters');
			
			// check domain layout with regex. Domain may consist of a-zA-Z0-9 and hiphen (and dots to separate labels). 
			// we will not enforce other domain rules
			
			try {
				SFDCStringValidationRule svr = new SFDCStringValidationRule('domain');
				svr.addWhitelistPattern(SFDCPatterns.Domain);
				svr.setMaximumLength(253);
				svr.setAllowNull(false);
				svr.assertValid(tmp);
			} catch (Exception e) {
				throw new SFDCValidationException('Input domain in URL is invalid');
			}
			
			// valid domain format - now check that it is *.salesforce.com or matches current domain
			if (tmp.endsWith('.salesforce.com') == false && 
					(SFDCStringUtils.isEmpty(currentDomain) == true || tmp.equals(currentDomain) == false)) {
				throw new SFDCValidationException('Input domain in URL must match *.salesforce.com or current domain');
			}
			
			// valid domain
			startPos = endPos;
			allowEmptyURI = true; // only allow null in URI if we had a domain
		}
		
		// continue to check rest of URL
		endPos = input.length();
		if (startPos < endPos)
			// only attempt to read rest of url if we have any more bytes (otherwise we will get an exception of out of boundaries read on input)
			tmp = input.substring(startPos, endPos);
		else
			tmp = null;
		
		try {
			SFDCStringValidationRule svr = new SFDCStringValidationRule('url');
			svr.addWhitelistPattern(SFDCPatterns.URL);
			svr.setMaximumLength(512);
			svr.setAllowNull(allowEmptyURI);
			svr.assertValid(tmp);
		} catch (Exception e) {
			throw new SFDCValidationException('Input URL is invalid');
		}

		return input;
	}	
}