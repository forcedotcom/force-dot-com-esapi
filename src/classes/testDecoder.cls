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
 * @author Sebastien Colladon (scolladon .at. salesforce.com) <a href="http://www.salesforce.com">Salesforce.com</a>
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
private class testDecoder {

    private class DecodeTest {
        public String inputStr;
        public String expectedOutput;
        public String errText;
        public Boolean expectedResult;
        public String encoding;

        public DecodeTest(String inputStr, String expectedOutput, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.expectedOutput = expectedOutput;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    private static final DecodeTest [] base64UrlDecodeTests = new DecodeTest[]{};


    static {
        base64UrlDecodeTests.add(new DecodeTest('dGVzdA', 'test', 'Valid #1', true));
        base64UrlDecodeTests.add(new DecodeTest('QCM_Ky0kKi8-VA', '@#?+-$*/>T', 'Valid #2', true));
    }

    static testMethod void testEncoderBase64UrlDecode() {
        for (DecodeTest t : base64UrlDecodeTests) {
            try {
                String ret = ESAPI.decoder().SFDC_BASE64_URLDECODE(t.inputStr).toString();
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