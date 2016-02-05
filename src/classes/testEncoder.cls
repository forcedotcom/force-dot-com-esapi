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
 * This class contains unit tests for validating the behavior of Apex classes
 * and triggers.
 *
 * Unit tests are class methods that verify whether a particular piece
 * of code is working properly. Unit test methods take no arguments,
 * commit no data to the database, and are flagged with the testMethod
 * keyword in the method definition.
 *
 * All test methods in an organization are executed whenever Apex code is deployed
 * to a production organization to confirm correctness, ensure code
 * coverage, and prevent regressions. All Apex classes are
 * required to have at least 75% code coverage in order to be deployed
 * to a production organization. In addition, all triggers must have some code coverage.
 * 
 * The @isTest class annotation indicates this class only contains test
 * methods. Classes defined with the @isTest annotation do not count against
 * the organization size limit for all Apex scripts.
 *
 * See the Apex Language Reference for more information about Testing and Code Coverage.
 */
@isTest
private class testEncoder {

    private class EncodeTest {
        public String inputStr;
        public String expectedOutput;
        public String errText;
        public Boolean expectedResult;
        public String encoding;
        
        public EncodeTest(String inputStr, String expectedOutput, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.expectedOutput = expectedOutput;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
        
        public EncodeTest(String inputStr, String encoding, String expectedOutput, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.encoding = encoding;
            this.expectedOutput = expectedOutput;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final EncodeTest [] htmlEncodeTests = new EncodeTest[]{};
    private static final EncodeTest [] jsEncodeTests = new EncodeTest[]{};
    private static final EncodeTest [] jsInHtmlEncodeTests = new EncodeTest[]{};
    private static final EncodeTest [] urlEncodeTests = new EncodeTest[]{};
    private static final EncodeTest [] urlEncodeWithEncodingTests = new EncodeTest[]{};
    private static final EncodeTest [] base64UrlEncodeTests = new EncodeTest[]{};

    
    static {
        htmlEncodeTests.add(new EncodeTest('abc', 'abc', 'Valid #1', true));
        htmlEncodeTests.add(new EncodeTest('abc<b>test</b>def', 'abc&lt;b&gt;test&lt;/b&gt;def', 'Valid #2', true));
        htmlEncodeTests.add(new EncodeTest('abc&lt;def', 'abc&amp;lt;def', 'Valid #3', true));
        htmlEncodeTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'abc&lt;fghgfh&amp;lt;&lt;sfdg&gt;&amp;amp;def', 'Valid #4', true));
        htmlEncodeTests.add(new EncodeTest('abc\'def', 'abc&#39;def', 'Valid #5', true));
        htmlEncodeTests.add(new EncodeTest('abc"def', 'abc&quot;def', 'Valid #6', true));

        jsEncodeTests.add(new EncodeTest('abc', 'abc', 'Valid #1', true));
        jsEncodeTests.add(new EncodeTest('abc<b>test</b>def', 'abc\\u003Cb\\u003Etest\\u003C\\/b\\u003Edef', 'Valid #2', true));
        jsEncodeTests.add(new EncodeTest('abc&lt;def', 'abc&lt;def', 'Valid #3', true));
        jsEncodeTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'abc\\u003Cfghgfh&lt;\\u003Csfdg\\u003E&amp;def', 'Valid #4', true));
        jsEncodeTests.add(new EncodeTest('abc\\def', 'abc\\\\def', 'Valid #5', true));
        jsEncodeTests.add(new EncodeTest('abc\'def', 'abc\\\'def', 'Valid #6', true));
        jsEncodeTests.add(new EncodeTest('abc\rdef', 'abc\\rdef', 'Valid #7', true));
        jsEncodeTests.add(new EncodeTest('abc\ndef', 'abc\\ndef', 'Valid #8', true));
        jsEncodeTests.add(new EncodeTest('abc"def', 'abc\\"def', 'Valid #9', true));
        jsEncodeTests.add(new EncodeTest('abc!--def', 'abc\\!--def', 'Valid #10', true));
        jsEncodeTests.add(new EncodeTest('abc<!--def', 'abc\\u003C\\!--def', 'Valid #11', true));
        jsEncodeTests.add(new EncodeTest('abc/def', 'abc\\/def', 'Valid #12', true));

        jsInHtmlEncodeTests.add(new EncodeTest('abc', 'abc', 'Valid #1', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc<b>test</b>def', 'abc&lt;b&gt;test&lt;/b&gt;def', 'Valid #2', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc&lt;def', 'abc\\\\&amp;lt;def', 'Valid #3', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'abc&lt;fghgfh\\\\&amp;lt;&lt;sfdg&gt;\\\\&amp;amp;def', 'Valid #4', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc\'def', 'abc\\&#39;def', 'Valid #5', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc"def', 'abc\\&quot;def', 'Valid #6', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc&def', 'abc\\\\&amp;def', 'Valid #7', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc\\def', 'abc\\\\def', 'Valid #8', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc\rdef', 'abc\\rdef', 'Valid #9', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc\ndef', 'abc\\ndef', 'Valid #10', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc<def', 'abc&lt;def', 'Valid #11', true));
        jsInHtmlEncodeTests.add(new EncodeTest('abc>def', 'abc&gt;def', 'Valid #12', true));

        urlEncodeTests.add(new EncodeTest('abc', 'abc', 'Valid #1', true));
        urlEncodeTests.add(new EncodeTest('abc<b>test</b>def', 'abc%3Cb%3Etest%3C%2Fb%3Edef', 'Valid #2', true));
        urlEncodeTests.add(new EncodeTest('abc&lt;def', 'abc%26lt%3Bdef', 'Valid #3', true));
        urlEncodeTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'abc%3Cfghgfh%26lt%3B%3Csfdg%3E%26amp%3Bdef', 'Valid #4', true));
        urlEncodeTests.add(new EncodeTest('abc\'def', 'abc%27def', 'Valid #5', true));
        urlEncodeTests.add(new EncodeTest('abc"def', 'abc%22def', 'Valid #6', true));
        urlEncodeTests.add(new EncodeTest('abc\rdef', 'abc%0Ddef', 'Valid #7', true));
        urlEncodeTests.add(new EncodeTest('abc\ndef', 'abc%0Adef', 'Valid #8', true));
        urlEncodeTests.add(new EncodeTest('abc' + EncodingUtil.urlDecode('%D7%A9', 'UTF-8') + 'def', 'abc%D7%A9def', 'Valid #9', true));

        urlEncodeWithEncodingTests.add(new EncodeTest('abc', 'UTF-8', 'abc', 'Valid #1', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc<b>test</b>def', 'UTF-8', 'abc%3Cb%3Etest%3C%2Fb%3Edef', 'Valid #2', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc&lt;def', 'UTF-8', 'abc%26lt%3Bdef', 'Valid #3', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'UTF-8', 'abc%3Cfghgfh%26lt%3B%3Csfdg%3E%26amp%3Bdef', 'Valid #4', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\'def', 'UTF-8', 'abc%27def', 'Valid #5', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc"def', 'UTF-8', 'abc%22def', 'Valid #6', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\rdef', 'UTF-8', 'abc%0Ddef', 'Valid #7', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\ndef', 'UTF-8', 'abc%0Adef', 'Valid #8', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc' + EncodingUtil.urlDecode('%D7%A9', 'UTF-8') + 'def', 'UTF-8', 'abc%D7%A9def', 'Valid #9', true));

        urlEncodeWithEncodingTests.add(new EncodeTest('abc', 'UTF-16', 'abc', 'Valid #1', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc<b>test</b>def', 'UTF-16', 'abc%FE%FF%00%3Cb%FE%FF%00%3Etest%FE%FF%00%3C%00%2Fb%FE%FF%00%3Edef', 'Valid #2', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc&lt;def', 'UTF-16', 'abc%FE%FF%00%26lt%FE%FF%00%3Bdef', 'Valid #3', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc<fghgfh&lt;<sfdg>&amp;def', 'UTF-16', 'abc%FE%FF%00%3Cfghgfh%FE%FF%00%26lt%FE%FF%00%3B%00%3Csfdg%FE%FF%00%3E%00%26amp%FE%FF%00%3Bdef', 'Valid #4', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\'def', 'UTF-16', 'abc%FE%FF%00%27def', 'Valid #5', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc"def', 'UTF-16', 'abc%FE%FF%00%22def', 'Valid #6', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\rdef', 'UTF-16', 'abc%FE%FF%00%0Ddef', 'Valid #7', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc\ndef', 'UTF-16', 'abc%FE%FF%00%0Adef', 'Valid #8', true));
        urlEncodeWithEncodingTests.add(new EncodeTest('abc' + EncodingUtil.urlDecode('%D7%A9', 'UTF-8') + 'def', 'UTF-16', 'abc%FE%FF%05%E9def', 'Valid #9', true));

        base64UrlEncodeTests.add(new EncodeTest('a', 'YQ', 'Valid #1', true));
        base64UrlEncodeTests.add(new EncodeTest('b', 'Yg', 'Valid #2', true));
        base64UrlEncodeTests.add(new EncodeTest('c', 'Yw', 'Valid #3', true));
        
    }

    static testMethod void testEncoderHtmlEncode() {
        for (EncodeTest t : htmlEncodeTests) {
            try {
                String ret = ESAPI.encoder().SFDC_HTMLENCODE(t.inputStr);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    static testMethod void testEncoderJsEncode() {
        for (EncodeTest t : jsEncodeTests) {
            try {
                String ret = ESAPI.encoder().SFDC_JSENCODE(t.inputStr);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    
    
    static testMethod void testEncoderJsInHtmlEncode() {
        for (EncodeTest t : jsInHtmlEncodeTests) {
            try {
                String ret = ESAPI.encoder().SFDC_JSINHTMLENCODE(t.inputStr);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.debug('expected: ' + t.expectedOutput);
                System.debug('observed: ' + ret);
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    static testMethod void testEncoderUrlEncode() {
        for (EncodeTest t : urlEncodeTests) {
            try {
                String ret = ESAPI.encoder().SFDC_URLENCODE(t.inputStr);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    static testMethod void testEncoderUrlEncodeWithEncoding() {
        for (EncodeTest t : urlEncodeWithEncodingTests) {
            try {
                String ret = ESAPI.encoder().SFDC_URLENCODE(t.inputStr, t.encoding);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }

    static testMethod void testEncoderBase64UrlEncode() {
        for (EncodeTest t : base64UrlEncodeTests) {
            try {
                String ret = ESAPI.encoder().SFDC_BASE64_URLENCODE(Blob.valueOf(t.inputStr));
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.expectedOutput), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }  
}