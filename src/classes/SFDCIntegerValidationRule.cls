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
 * A class to verify integer values
 */
global with sharing class SFDCIntegerValidationRule extends SFDCBaseValidationRule {
	
	private Integer minValue = 0;
	private Integer maxValue = 0;
	
	// Set maximum string length to be more than enough for any integer value we can handle
	private Integer maxStrLength = 50;
	
	private static final Pattern INTEGER_PATTERN = null;

	static {
		INTEGER_PATTERN = Pattern.compile(SFDCPatterns.IntegerStr);
	}
	
	private SFDCStringValidationRule svrule = null; 
	
	private SFDCIntegerValidationRule(String typeName) {
		// prevent use of this constructor - so that minValue and maxValue are guaranteed to be set
		super(typeName);
	}

	public SFDCIntegerValidationRule(String typeName, Integer minValue, Integer maxValue) {
		super(typeName);
		
		if (minValue > maxValue)
			throw new SFDCValidator.SFDCValidationException('maxValue must be larger than minValue');
		
		this.minValue = minValue;
		this.maxValue = maxValue;
		
		// get default regex string validator for integer
		svrule = readDefaultIntegerRule();
	}
	
	private SFDCStringValidationRule readDefaultIntegerRule() {
		SFDCStringValidationRule svr = new SFDCStringValidationRule( 'integerrule', INTEGER_PATTERN.pattern() );
		svr.setMaximumLength(getMaxIntegerStrLength());
		svr.setAllowNull( false );
		return svr;
	}

    /**
     * This function will perform the following tests, and throw an exception if any of them fail.
     *   - is null or zero bytes and allow null was set to false
     *   - value is larger than maxValue
     *   - value is smaller than minValue
     *   - value is not a valid integer number
     * If all tests passed it will return the input as Integer 
     */
	public Integer getValid(String input ) {
		return safelyParse(input);
	}

	private Integer safelyParse(String input) {
	    if ( SFDCStringUtils.isEmpty(input) ) {
			if (isAllowNull()) {
				return null;
			}
			throw new SFDCValidator.SFDCValidationException('Input integer required');
	    }
	    
	    // make sure string contains only valid integer characters using regex
	    try {
	    	svrule.assertValid(input);
	    } catch (Exception e) {
	    	// String did not match the regex pattern or other basic string rule checks
	    	throw new SFDCValidator.SFDCValidationException('Invalid integer input');
	    }
	    
		// RegEx is ok , so try to convert string to integer
		Integer i;
		try {
			i = Integer.valueOf(input);
		} catch (Exception e) {
			throw new SFDCValidator.SFDCValidationException('Invalid integer input format');
		}
		
		// validate min and max
		if (i < minValue) {
			throw new SFDCValidator.SFDCValidationException('Invalid integer input must be between ' + minValue + ' and ' + maxValue);
		}
		if (i > maxValue) {
			throw new SFDCValidator.SFDCValidationException('Invalid integer input must be between ' + minValue + ' and ' + maxValue);
		}
					
		return i;
	}

	/**
	 * @return the max integer string length
	 */
	private Integer getMaxIntegerStrLength() {
		return maxStrLength;
	}
}