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
 * A string validator class. This will check the string against black list and white list RegEx patterns,
 * check null, min length, and max length.
 */
global with sharing class SFDCStringValidationRule extends SFDCBaseValidationRule {

    private List<Pattern> whitelistPatterns = new List<Pattern>();
    private List<Pattern> blacklistPatterns = new List<Pattern>();
    private Integer minLength = 0;
    private Integer maxLength = 0;

    public SFDCStringValidationRule( String typeName ) {
        super( typeName );
    }

    public SFDCStringValidationRule( String typeName, String whitelistPattern ) {
        super( typeName );
        addWhitelistPattern( whitelistPattern );
    }

    /**
     * Add pattern p to the whitelist patterns. throw an exception if failed to add.
     */
    public void addWhitelistPattern( String p ) {
         if (p == null) {
             throw new SFDCValidator.SFDCValidationException('Pattern cannot be null');
         }
        try {
            whitelistPatterns.add( Pattern.compile( p ) );
        } catch( Exception e ) {
            throw new SFDCValidator.SFDCValidationException( 'Validation misconfiguration, problem with specified pattern');
        }
    }
    

    /**
     * Add pattern p to the whitelist patterns. throw an exception if failed to add.
     */
    public void addWhitelistPattern( Pattern p ) {
        if (p == null) {
           throw new SFDCValidator.SFDCValidationException('Pattern cannot be null');
        }
        whitelistPatterns.add( p );
    }

    /**
     * Add pattern p to the blacklist patterns. throw an exception if failed to add.
     */
    public void addBlacklistPattern( String p ) {
         if (p == null) {
             throw new SFDCValidator.SFDCValidationException('Pattern cannot be null');
         }
        try {
            blacklistPatterns.add( Pattern.compile( p ) );
        } catch( Exception e ) {
            throw new SFDCValidator.SFDCValidationException( 'Validation misconfiguration, problem with specified pattern');
        }
    }

    /**
     * Add pattern p to the blacklist patterns. throw an exception if failed to add.
     */
    public void addBlacklistPattern( Pattern p ) {
         if (p == null) {
             throw new SFDCValidator.SFDCValidationException('Pattern cannot be null');
         }
        blacklistPatterns.add( p );
    }
    
    public void setMinimumLength( Integer length ) {
        minLength = length;
    }
    
    public void setMaximumLength( Integer length ) {
        maxLength = length;
    }

    /**
     * This function will perform the following tests, and throw an exception if any of them fail.
     *   - is null or zero bytes and allow null was set to false
     *   - minimum length
     *   - maximum length
     *   - input matches all whitelist patterns added
     *   - input does not match any blacklist patterns added
     * If all tests passed it will just finish without any exceptions 
     */
    public void assertValid(String input ) {

        if ( SFDCStringUtils.isEmpty(input) ) {
            if (isAllowNull())
                return;
            throw new SFDCValidator.SFDCValidationException('SFDCStringValidationRule - Input required');
        }
        
        // check length
        if (input.length() < minLength) {
        	throw new SFDCValidator.SFDCValidationException('SFDCStringValidationRule - Input is too short');
        }

        if (input.length() > maxLength) {
        	throw new SFDCValidator.SFDCValidationException('SFDCStringValidationRule - Input is too long');
        }
        
        // check whitelist patterns - the input must match each white list pattern
        // TODO - should we change this so it is ok if matches one? 
        for (Pattern p : whitelistPatterns) {
            if ( !p.matcher(input).matches() ) {
                throw new SFDCValidator.SFDCValidationException('SFDCStringValidationRule - Invalid input, please conform to pattern.');
            }
        }
        
        // check blacklist patterns - fail if it matches any of the patterns
        for (Pattern p : blacklistPatterns) {
            if ( p.matcher(input).matches() ) {
            	throw new SFDCValidator.SFDCValidationException('SFDCStringValidationRule - Invalid input, dangerous input matching detected.');
            }
        }
        
        // validation passed - don't throw exception
    }
}