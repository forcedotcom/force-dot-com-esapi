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
private class testValidator {

    private class CreditCardTest {
        public String cardStr;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public CreditCardTest(String cardStr, String errText, Boolean allowNull, Boolean expectedResult) {
            this.cardStr = cardStr;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final CreditCardTest [] ccTests = new CreditCardTest[]{};
    
    static {
        ccTests.add(new CreditCardTest('4111111111111111', 'Valid basic test - 4111111111111111', false, true));
        ccTests.add(new CreditCardTest('4111-1111-1111-1111', 'Valid basic test dashes - 4111-1111-1111-1111', false, true));
        ccTests.add(new CreditCardTest('4111 1111 1111 1111', 'Valid basic test spaces - 4111 1111 1111 1111', false, true));
        
        ccTests.add(new CreditCardTest('111-1111-1111-1111', 'Invalid missing digit - 111-1111-1111-1111', false, false));
        ccTests.add(new CreditCardTest('4111-111-1111-1111', 'Invalid missing digit - 4111-111-1111-1111', false, false));
        ccTests.add(new CreditCardTest('4111-1111-111-1111', 'Invalid missing digit - 4111-1111-111-1111', false, false));
        ccTests.add(new CreditCardTest('4111-1111-1111-111', 'Invalid missing digit - 4111-1111-1111-111', false, false));
        
        ccTests.add(new CreditCardTest('4111-1111-1111-1112', 'Invalid incorrect digit - 4111-1111-1111-1112', false, false));
        ccTests.add(new CreditCardTest('4111-6789-0123-4567', 'Invalid incorrect digits - 4111-6789-0123-4567', false, false));
        
        ccTests.add(new CreditCardTest('41111-6789-0123-4567', 'Invalid incorrect length - 41111-6789-0123-4567', false, false));
        ccTests.add(new CreditCardTest('1111-16789-0123-4567', 'Invalid incorrect length - 1111-16789-0123-4567', false, false));
        ccTests.add(new CreditCardTest('1111-6789-10123-4567', 'Invalid incorrect length - 1111-6789-10123-4567', false, false));
        ccTests.add(new CreditCardTest('1111-6789-0123-14567', 'Invalid incorrect length - 1111-6789-0123-14567', false, false));
        ccTests.add(new CreditCardTest('1111-6789-0123-145', 'Invalid incorrect length - 1111-6789-0123-145', false, false));
        
        ccTests.add(new CreditCardTest('4111a1111a1111a1111', 'Invalid character - 4111a1111a1111a1111', false, false));
        ccTests.add(new CreditCardTest('a4111-1111-1111-1111', 'Invalid character - a4111-1111-1111-1111', false, false));
        
        ccTests.add(new CreditCardTest(null, 'Invalid null', false, false));
        ccTests.add(new CreditCardTest(null, 'Valid null', true, true));
        ccTests.add(new CreditCardTest('', 'Invalid empty', false, false));
        ccTests.add(new CreditCardTest('', 'Valid empty', true, true));
        
        //ccTests.add(new CreditCardTest('378282246310005', 'Valid - American Express - 378282246310005', false, true)); // card not supported
        //ccTests.add(new CreditCardTest('371449635398431', 'Valid - American Express - 371449635398431', false, true)); // card not supported
        //ccTests.add(new CreditCardTest('378734493671000', 'Valid - American Express Corporate - 378734493671000', false, true));
        ccTests.add(new CreditCardTest('5610591081018250', 'Valid - Australian BankCard - 5610591081018250', false, true));
        //ccTests.add(new CreditCardTest('30569309025904', 'Valid - Diners Club - 30569309025904', false, true)); // card not supported
        //ccTests.add(new CreditCardTest('38520000023237', 'Valid - Diners Club - 38520000023237', false, true)); // card not supported
        ccTests.add(new CreditCardTest('6011111111111117', 'Valid - Discover - 6011111111111117', false, true));
        ccTests.add(new CreditCardTest('6011000990139424', 'Valid - Discover - 6011000990139424', false, true));
        ccTests.add(new CreditCardTest('3530111333300000', 'Valid - JCB - 3530111333300000', false, true));
        ccTests.add(new CreditCardTest('3566002020360505', 'Valid - JCB - 3566002020360505', false, true));
        ccTests.add(new CreditCardTest('5555555555554444', 'Valid - MasterCard - 5555555555554444', false, true));
        ccTests.add(new CreditCardTest('5105105105105100', 'Valid - MasterCard - 5105105105105100', false, true));
        ccTests.add(new CreditCardTest('4111111111111111', 'Valid - Visa - 4111111111111111', false, true));
        ccTests.add(new CreditCardTest('4012888888881881', 'Valid - Visa - 4012888888881881', false, true));
        //ccTests.add(new CreditCardTest('4222222222222', 'Valid - Visa - 4222222222222', false, true)); // not supported (not 16 digits card)
    }

    static testMethod void testValidatorIsValidCreditCard() {
        
        for (CreditCardTest t : ccTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidCreditCard(t.cardStr, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidCreditCard() {
        for (CreditCardTest t : ccTests) {
            try {
                String ret = ESAPI.validator().getValidCreditCard(t.cardStr, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.cardStr), t.errText);
                else
                    System.assert(t.allowNull && t.cardStr == null, t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class DateTest {
        public String dateStr;
        public String dateFormat;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public DateTest(String dateStr, String dateFormat, String errText, Boolean allowNull, Boolean expectedResult) {
            this.dateStr = dateStr;
            this.dateFormat = dateFormat;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final DateTest [] dateTests = new DateTest[]{};
    
    static {
        
        // test function structure
        
        dateTests.add(new DateTest('25/10/99', SFDCPatterns.Date1, 'Valid basic test - 25/10/99 - Date1 - dd/mm/yy', false, true));
        dateTests.add(new DateTest('25/10/1999', SFDCPatterns.Date1, 'Invalid basic test - 25/10/1999 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('251099', SFDCPatterns.Date1, 'Invalid basic test - 251099 - Date1 - dd/mm/yy', false, false));
        
        dateTests.add(new DateTest(null, SFDCPatterns.Date1, 'Invalid basic test - null - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest(null, SFDCPatterns.Date1, 'Invalid basic test - null - Date1 - dd/mm/yy', true, true));
        dateTests.add(new DateTest('', SFDCPatterns.Date1, 'Invalid basic test - empty - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('', SFDCPatterns.Date1, 'Invalid basic test - empty - Date1 - dd/mm/yy', true, true));
        
        dateTests.add(new DateTest('25/10/99', null, 'Invalid basic test - null format', false, false));
        
        dateTests.add(new DateTest('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', '^[A]*$', 'Invalid basic test - too long', false, false));
        
        // test regex formats
        
        // dd/mm/yy
        dateTests.add(new DateTest('25/10/99', SFDCPatterns.Date1, 'Valid basic test - 25/10/99 - Date1 - dd/mm/yy', false, true));
        dateTests.add(new DateTest('25/25/99', SFDCPatterns.Date1, 'Invalid month value - 25/25/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('25/aa/99', SFDCPatterns.Date1, 'Invalid month value - 25/aa/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('25//99', SFDCPatterns.Date1, 'Invalid empty month value - 25//99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest(' 25/10/99', SFDCPatterns.Date1, 'Invalid value -  25/10/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('25/10/99 ', SFDCPatterns.Date1, 'Invalid value - 25/10/99  - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('25-10-99 ', SFDCPatterns.Date1, 'Invalid value - 25-10-99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('32/10/99 ', SFDCPatterns.Date1, 'Invalid value - 32/10/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('31/00/99 ', SFDCPatterns.Date1, 'Invalid value - 31/00/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('00/01/99 ', SFDCPatterns.Date1, 'Invalid value - 00/01/99 - Date1 - dd/mm/yy', false, false));
        dateTests.add(new DateTest('29/01/9 ', SFDCPatterns.Date1, 'Invalid value - 29/01/9 - Date1 - dd/mm/yy', false, false));
        
        // (d)d/-.(m)m/-.(yy)yy
        dateTests.add(new DateTest('25/10/99', SFDCPatterns.Date4, 'Valid test - 25/10/99 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('5/10/1999', SFDCPatterns.Date4, 'Valid test - 5/10/1999 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('15/2/08', SFDCPatterns.Date4, 'Valid test - 15/2/08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('15-2-08', SFDCPatterns.Date4, 'Valid test - 15-2-08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('15.2.08', SFDCPatterns.Date4, 'Valid test - 15.2.08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('15.02.08', SFDCPatterns.Date4, 'Valid test - 15.02.08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, true));
        dateTests.add(new DateTest('15//08', SFDCPatterns.Date4, 'Valid test - 15//08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, false));
        dateTests.add(new DateTest('15.a.08', SFDCPatterns.Date4, 'Valid test - 15.a.08 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, false));
        dateTests.add(new DateTest('2008/10/10', SFDCPatterns.Date4, 'Valid test - 2008/10/10 - Date4 - (d)d/-.(m)m/-.(yy)yy', false, false));
        dateTests.add(new DateTest('', SFDCPatterns.Date4, 'Valid test - empty - Date4 - (d)d/-.(m)m/-.(yy)yy', false, false));
    }

    static testMethod void testValidatorIsValidDate() {
        
        for (DateTest t : dateTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().SFDC_isValidDate(t.dateStr, t.dateFormat, t.allowNull)  , t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidDate() {
        for (DateTest t : dateTests) {
            try {
                String ret = ESAPI.validator().SFDC_getValidDate(t.dateStr, t.dateFormat, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.dateStr), t.errText);
                else
                    System.assert(t.allowNull && t.dateStr == null, t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class DoubleTest {
        public String inputStr;
        public Double minValue;
        public Double maxValue;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public DoubleTest(String inputStr, Double minValue, Double maxValue, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.minValue = minValue;
            this.maxValue = maxValue;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final DoubleTest [] doubleTests = new DoubleTest[]{};
    
    static {
        doubleTests.add(new DoubleTest('1.964', (Double)(-2.0), (Double)(2.0), 'Valid #1', false, true));
        doubleTests.add(new DoubleTest('+1.964', (Double)(-2.0), (Double)(2.0), 'Valid #2', false, true));
        doubleTests.add(new DoubleTest('-3.38475', (Double)(-5.0), (Double)(-2.0), 'Valid #3', false, true));
        doubleTests.add(new DoubleTest('1', (Double)(0), (Double)(2), 'Valid #4', false, true));
        doubleTests.add(new DoubleTest('0', (Double)(-2.0), (Double)(0), 'Valid #5', false, true));
        doubleTests.add(new DoubleTest('0', (Double)(0), (Double)(0), 'Valid #6', false, true));
        doubleTests.add(new DoubleTest(null, (Double)(1.0), (Double)(2.0), 'Valid #7', true, true));
        doubleTests.add(new DoubleTest('1.0E+3', (Double)(500), (Double)(2000), 'Valid #8', false, true));
        
        doubleTests.add(new DoubleTest('1.964', (Double)(2.0), (Double)(1.0), 'Invalid #1', false, false));
        doubleTests.add(new DoubleTest(null, (Double)(1.0), (Double)(2.0), 'Invalid #2', false, false));
        doubleTests.add(new DoubleTest('', (Double)(1.0), (Double)(2.0), 'Invalid #3', false, false));
        doubleTests.add(new DoubleTest('1.0', (Double)(2.0), (Double)(3.0), 'Invalid #4', false, false));
        doubleTests.add(new DoubleTest('5.0', (Double)(2.0), (Double)(3.0), 'Invalid #5', false, false));
        doubleTests.add(new DoubleTest('2.5a', (Double)(2.0), (Double)(3.0), 'Invalid #6', false, false));
        doubleTests.add(new DoubleTest('2e', (Double)(2.0), (Double)(3.0), 'Invalid #7', false, false));
        doubleTests.add(new DoubleTest('1.e+50', (Double)(2.0), (Double)(3.0), 'Invalid #8', false, false));
        doubleTests.add(new DoubleTest('7.237005577332262213973186563043e+75', (Double)(2.0), (Double)(3.0), 'Invalid #9', false, false));
        doubleTests.add(new DoubleTest('10+10', (Double)(500), (Double)(2000), 'Invalid #10', false, false));
    }

    static testMethod void testValidatorIsValidDouble() {
        for (DoubleTest t : doubleTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidDouble(t.inputStr, t.minValue, t.maxValue, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidDouble() {
        for (DoubleTest t : doubleTests) {
            try {
                Double ret = ESAPI.validator().getValidDouble(t.inputStr, t.minValue, t.maxValue, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to Double.valueOf(input) unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret == Double.valueOf(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class IntTest {
        public String inputStr;
        public Integer minValue;
        public Integer maxValue;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public IntTest(String inputStr, Integer minValue, Integer maxValue, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.minValue = minValue;
            this.maxValue = maxValue;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final IntTest [] intTests = new IntTest[]{};
    
    static {
        intTests.add(new IntTest('1', -2, 2, 'Valid #1', false, true));
        intTests.add(new IntTest('-3', -5, -2, 'Valid #2', false, true));
        intTests.add(new IntTest('1', 0, 2, 'Valid #3', false, true));
        intTests.add(new IntTest('0', -2, 0, 'Valid #4', false, true));
        intTests.add(new IntTest('0', 0, 0, 'Valid #5', false, true));
        intTests.add(new IntTest(null, 1, 2, 'Valid #6', true, true));
        intTests.add(new IntTest('1000000', 500000, 2000000, 'Valid #7', false, true));
        intTests.add(new IntTest('906842624', 906842623, 906842625, 'Valid #8', false, true));
        intTests.add(new IntTest('+1', -2, 2, 'Valid #9', false, true));
        
        intTests.add(new IntTest('1', 2, 1, 'Invalid #1', false, false));
        intTests.add(new IntTest(null, 1, 2, 'Invalid #2', false, false));
        intTests.add(new IntTest('', 1, 2, 'Invalid #3', false, false));
        intTests.add(new IntTest('1', 2, 3, 'Invalid #4', false, false));
        intTests.add(new IntTest('5', 2, 3, 'Invalid #5', false, false));
        intTests.add(new IntTest('2a', 1, 3, 'Invalid #6', false, false));
        intTests.add(new IntTest('2.0', 1, 3, 'Invalid #7', false, false));
        intTests.add(new IntTest(' 10', 5, 20, 'Invalid #10', false, false));
        intTests.add(new IntTest('10 ', 5, 20, 'Invalid #11', false, false));
        intTests.add(new IntTest('5899906842624', 906842623, 906842625, 'Invalid #13', false, false)); 
    }

    static testMethod void testValidatorIsValidInteger() {
        for (IntTest t : intTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidInteger(t.inputStr, t.minValue, t.maxValue, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidInteger() {
        for (IntTest t : intTests) {
            try {
                Integer ret = ESAPI.validator().getValidInteger(t.inputStr, t.minValue, t.maxValue, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to Integer.valueOf(input) unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret == Integer.valueOf(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class NumberTest {
        public String inputStr;
        public Long minValue;
        public Long maxValue;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public NumberTest(String inputStr, Long minValue, Long maxValue, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.minValue = minValue;
            this.maxValue = maxValue;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final NumberTest [] numberTests = new NumberTest[]{};
    
    static {
        numberTests.add(new NumberTest('1', -2, 2, 'Valid #1', false, true));
        numberTests.add(new NumberTest('-3', -5, -2, 'Valid #2', false, true));
        numberTests.add(new NumberTest('1', 0, 2, 'Valid #3', false, true));
        numberTests.add(new NumberTest('0', -2, 0, 'Valid #4', false, true));
        numberTests.add(new NumberTest('0', 0, 0, 'Valid #5', false, true));
        numberTests.add(new NumberTest(null, 1, 2, 'Valid #6', true, true));
        numberTests.add(new NumberTest('1000000', 500000, 2000000, 'Valid #7', false, true));
        numberTests.add(new NumberTest('1125899906842624', 1125899906842623L, 1125899906842625L, 'Valid #8', false, true));
        
        numberTests.add(new NumberTest('1', 2, 1, 'Invalid #1', false, false));
        numberTests.add(new NumberTest(null, 1, 2, 'Invalid #2', false, false));
        numberTests.add(new NumberTest('', 1, 2, 'Invalid #3', false, false));
        numberTests.add(new NumberTest('1', 2, 3, 'Invalid #4', false, false));
        numberTests.add(new NumberTest('5', 2, 3, 'Invalid #5', false, false));
        numberTests.add(new NumberTest('2a', 1, 3, 'Invalid #6', false, false));
        //numberTests.add(new NumberTest('2.0', 1, 3, 'Invalid #7', false, false)); // number is internally a double - so this is valid.
        numberTests.add(new NumberTest(' 10', 5, 20, 'Invalid #8', false, false));
        numberTests.add(new NumberTest('10 ', 5, 20, 'Invalid #9', false, false));
    }

    static testMethod void testValidatorIsValidNumber() {
        for (NumberTest t : numberTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidNumber(t.inputStr, t.minValue, t.maxValue, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidNumber() {
        for (NumberTest t : numberTests) {
            try {
                Double ret = ESAPI.validator().getValidNumber(t.inputStr, t.minValue, t.maxValue, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to Double.valueOf(input) unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret == Double.valueOf(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class ListItemTest {
        public String inputStr;
        public Set<String> validItems;
        public String errText;
        public Boolean expectedResult;
        
        public ListItemTest(String inputStr, Set<String> validItems, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.validItems = validItems;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final ListItemTest [] listItemTests = new ListItemTest[]{};
    private static final Set<String> listItems1 = new Set<String>{'US', 'CANADA', 'MEXICO', 'ksjdfhg^$ \t%^DSFGs'};
    private static final Set<String> listItems2 = new Set<String>{'US'};
    private static final Set<String> listItems3 = new Set<String>{};
    private static final Set<String> listItems4 = new Set<String>{'', null};
    
    static {
        listItemTests.add(new ListItemTest('US', listItems1, 'Valid #1', true));
        listItemTests.add(new ListItemTest('US', listItems2, 'Valid #2', true));
        listItemTests.add(new ListItemTest('CANADA', listItems1, 'Valid #3', true));
        listItemTests.add(new ListItemTest('MEXICO', listItems1, 'Valid #4', true));
        listItemTests.add(new ListItemTest('ksjdfhg^$ \t%^DSFGs', listItems1, 'Valid #5', true));
        listItemTests.add(new ListItemTest('', listItems4, 'Valid #6', true));
        listItemTests.add(new ListItemTest(null, listItems4, 'Valid #7', true));
        
        listItemTests.add(new ListItemTest('', listItems1, 'Invalid #1', false));
        listItemTests.add(new ListItemTest(null, listItems1, 'Invalid #2', false));
        listItemTests.add(new ListItemTest('', listItems2, 'Invalid #3', false));
        listItemTests.add(new ListItemTest(null, listItems2, 'Invalid #4', false));
        listItemTests.add(new ListItemTest('', listItems3, 'Invalid #5', false));
        listItemTests.add(new ListItemTest(null, listItems3, 'Invalid #6', false));
        listItemTests.add(new ListItemTest('', null, 'Invalid #7', false));
        listItemTests.add(new ListItemTest(null, null, 'Invalid #8', false));
        listItemTests.add(new ListItemTest('EU', listItems1, 'Invalid #9', false));
        listItemTests.add(new ListItemTest('us', listItems1, 'Invalid #10', false));
        listItemTests.add(new ListItemTest('ksjdfhg^$  %^DSFGs', listItems1, 'Invalid #11', false));
        listItemTests.add(new ListItemTest('USA', listItems1, 'Invalid #12', false));
        listItemTests.add(new ListItemTest('AUS', listItems1, 'Invalid #13', false));
        listItemTests.add(new ListItemTest(' US', listItems1, 'Invalid #14', false));
        listItemTests.add(new ListItemTest('US ', listItems1, 'Invalid #15', false));
    }

    static testMethod void testValidatorIsValidListItem() {
        for (ListItemTest t : listItemTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidListItem(t.inputStr, t.validItems), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidListItem() {
        for (ListItemTest t : listItemTests) {
            try {
                String ret = ESAPI.validator().getValidListItem(t.inputStr, t.validItems);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was also null
                if (ret != null)
                    System.assert(ret.equals(t.inputStr), t.errText);
                else
                    System.assert(ret == t.inputStr, t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class FileContentTest {
        public String inputStr;
        public Integer maxBytes;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public FileContentTest(String inputStr, Integer maxBytes, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.maxBytes = maxBytes;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final FileContentTest [] fileContentTests = new FileContentTest[]{};
    
    static {
        fileContentTests.add(new FileContentTest('1', 1, 'Valid #1', false, true));
        fileContentTests.add(new FileContentTest('abc', 3, 'Valid #2', false, true));
        fileContentTests.add(new FileContentTest('abc', 300, 'Valid #3', false, true));
        fileContentTests.add(new FileContentTest(null, 1, 'Valid #4', true, true));
        fileContentTests.add(new FileContentTest('', 1, 'Valid #5', true, true));
        
        fileContentTests.add(new FileContentTest('abc', 2, 'Invalid #1', false, false));
        fileContentTests.add(new FileContentTest(null, 1, 'Invalid #2', false, false));
        fileContentTests.add(new FileContentTest('', 1, 'Invalid #3', false, false));
    }

    static testMethod void testValidatorIsValidfileContent() {
        for (FileContentTest t : fileContentTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidFileContent(t.inputStr, t.maxBytes, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidFileContent() {
        for (FileContentTest t : fileContentTests) {
            try {
                String ret = ESAPI.validator().getValidFileContent(t.inputStr, t.maxBytes, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class PrintableTest {
        public String inputStr;
        public Integer maxBytes;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public PrintableTest(String inputStr, Integer maxBytes, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.maxBytes = maxBytes;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final PrintableTest [] printableTests = new PrintableTest[]{};
    
    static {
        printableTests.add(new PrintableTest('1', 1, 'Valid #1', false, true));
        printableTests.add(new PrintableTest('abc', 3, 'Valid #2', false, true));
        printableTests.add(new PrintableTest('abc', 300, 'Valid #3', false, true));
        printableTests.add(new PrintableTest(null, 1, 'Valid #4', true, true));
        printableTests.add(new PrintableTest('', 1, 'Valid #5', true, true));
        printableTests.add(new PrintableTest('ab487sjhdg$%^#$%^&L>PO:c ~', 100, 'Valid #6', false, true));
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%20', 'UTF-8'), 10, 'Valid #7', false, true));
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%7E', 'UTF-8'), 10, 'Valid #8', false, true));
        
        printableTests.add(new PrintableTest('abc', 2, 'Invalid #1', false, false));
        printableTests.add(new PrintableTest(null, 1, 'Invalid #2', false, false));
        printableTests.add(new PrintableTest('', 1, 'Invalid #3', false, false));
        printableTests.add(new PrintableTest('\r', 1, 'Invalid #4', false, false));
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%1F', 'UTF-8'), 10, 'Invalid #5', false, false));
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%7F', 'UTF-8'), 10, 'Valid #8', false, false));
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 10, 'Valid #9', false, false)); // ascii 0x80
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%C3%BF', 'UTF-8'), 10, 'Valid #10', false, false)); // ascii 0xFF
        printableTests.add(new PrintableTest(EncodingUtil.urlDecode('%D7%A9', 'UTF-8'), 10, 'Valid #11', false, false)); // unicode U+05E9
    }

    static testMethod void testValidatorIsValidPrintable() {
        for (PrintableTest t : printableTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidPrintable(t.inputStr, t.maxBytes, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidPrintable() {
        for (PrintableTest t : printableTests) {
            try {
                String ret = ESAPI.validator().getValidPrintable(t.inputStr, t.maxBytes, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    

    private class FileNameDefaultExtensionsTest {
        public String inputStr;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public FileNameDefaultExtensionsTest(String inputStr, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final FileNameDefaultExtensionsTest [] fileNameDefaultExtensionsTests = new FileNameDefaultExtensionsTest[]{};
    
    static {
        
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('1.txt', 'Valid #1', false, true));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(null, 'Valid #2', true, true));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('', 'Valid #3', true, true));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('()+. \'&,-=_0123456789abcdefhhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.zip', 'Valid #4', false, true));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('1.TXT', 'Valid #5', false, true));
        
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(null, 'Invalid #1', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('', 'Invalid #2', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('\r', 'Invalid #3', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(EncodingUtil.urlDecode('%1F', 'UTF-8'), 'Invalid #4', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(EncodingUtil.urlDecode('%7F', 'UTF-8'), 'Invalid #5', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 'Invalid #6', false, false)); // ascii 0x80
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(EncodingUtil.urlDecode('%C3%BF', 'UTF-8'), 'Invalid #7', false, false)); // ascii 0xFF
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest(EncodingUtil.urlDecode('%D7%A9', 'UTF-8'), 'Invalid #8', false, false)); // unicode U+05E9
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('ab487sjhdg$%^#$%^&L>PO:c ~', 'Invalid #9', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('01234567890123456789012345678901234567890123456789'
            + '01234567890123456789012345678901234567890123456789'
            + '01234567890123456789012345678901234567890123456789'
            + '01234567890123456789012345678901234567890123456789'
            + '01234567890123456789012345678901234567890123456789'
            + '01234567890123456789012345678901234567890123456789.txt', 'Invalid #10 (too long)', false, false));
        fileNameDefaultExtensionsTests.add(new FileNameDefaultExtensionsTest('1.exe', 'Valid #10', false, false));
        
    }

    static testMethod void testValidatorIsValidFileNameDefaultExtensions() {
        for (FileNameDefaultExtensionsTest t : fileNameDefaultExtensionsTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().SFDC_isValidFileName(t.inputStr, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidFileNameDefaultExtensions() {
        for (FileNameDefaultExtensionsTest t : fileNameDefaultExtensionsTests) {
            try {
                String ret = ESAPI.validator().SFDC_getValidFileName(t.inputStr, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }

    private class FileNameTest {
        public String inputStr;
        public List<String> fileExtensions;
        public String errText;
        public Boolean allowNull;
        public Boolean expectedResult;
        
        public FileNameTest(String inputStr, List<String> fileExtensions, String errText, Boolean allowNull, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.fileExtensions = fileExtensions;
            this.errText = errText;
            this.allowNull = allowNull;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final FileNameTest [] fileNameTests = new FileNameTest[]{};
    private static final List<String> fileExtensions1 = new List<String>{'.txt', '.jpg', '.zip'};
    private static final List<String> fileExtensions2 = new List<String>{'.txt'};
    private static final List<String> fileExtensions3 = new List<String>{};
    private static final List<String> fileExtensions4 = new List<String>{'', null};
    
    static {
        fileNameTests.add(new FileNameTest('1.txt', fileExtensions1, 'Valid #1', false, true));
        fileNameTests.add(new FileNameTest('1.TXT', fileExtensions1, 'Valid #2', false, true));
        fileNameTests.add(new FileNameTest('1.txt', fileExtensions2, 'Valid #3', false, true));
        fileNameTests.add(new FileNameTest('1.TXT', fileExtensions2, 'Valid #4', false, true));
        fileNameTests.add(new FileNameTest('1.JPG', fileExtensions1, 'Valid #5', false, true));
        fileNameTests.add(new FileNameTest('1.ZIP', fileExtensions1, 'Valid #6', false, true));
        fileNameTests.add(new FileNameTest('', fileExtensions4, 'Valid #7', true, true));
        fileNameTests.add(new FileNameTest(null, fileExtensions4, 'Valid #8', true, true));
        fileNameTests.add(new FileNameTest('', fileExtensions1, 'Valid #9', true, true));
        fileNameTests.add(new FileNameTest(null, fileExtensions1, 'Valid #10', true, true));
        fileNameTests.add(new FileNameTest('', fileExtensions3, 'Valid #11', true, true));
        fileNameTests.add(new FileNameTest(null, fileExtensions3, 'Valid #12', true, true));
        fileNameTests.add(new FileNameTest('1.exe.txt', fileExtensions1, 'Valid #13', false, true));

        fileNameTests.add(new FileNameTest('1.JPG', fileExtensions2, 'Invalid #1', false, false));
        fileNameTests.add(new FileNameTest('1.ZIP', fileExtensions2, 'Invalid #2', false, false));
        fileNameTests.add(new FileNameTest('1.JPG', fileExtensions3, 'Invalid #3', false, false));
        fileNameTests.add(new FileNameTest('1.ZIP', fileExtensions3, 'Invalid #4', false, false));
        fileNameTests.add(new FileNameTest('1.JPG', fileExtensions4, 'Invalid #5', false, false));
        fileNameTests.add(new FileNameTest('1.ZIP', fileExtensions4, 'Invalid #6', false, false));
        fileNameTests.add(new FileNameTest('', fileExtensions1, 'Invalid #7', false, false));
        fileNameTests.add(new FileNameTest(null, fileExtensions1, 'Invalid #8', false, false));
        fileNameTests.add(new FileNameTest('', fileExtensions3, 'Invalid #9', false, false));
        fileNameTests.add(new FileNameTest(null, fileExtensions3, 'Invalid #10', false, false));
        fileNameTests.add(new FileNameTest('', fileExtensions4, 'Invalid #11', false, false));
        fileNameTests.add(new FileNameTest(null, fileExtensions4, 'Invalid #12', false, false));
        fileNameTests.add(new FileNameTest('1.exe', fileExtensions1, 'Invalid #13', false, false));
        fileNameTests.add(new FileNameTest('1.exetxt', fileExtensions1, 'Invalid #14', false, false));
        fileNameTests.add(new FileNameTest('1.txt.exe', fileExtensions1, 'Invalid #15', false, false));
    }

    static testMethod void testValidatorIsValidFileName() {
        for (FileNameTest t : fileNameTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().SFDC_isValidFileName(t.inputStr, t.fileExtensions, t.allowNull), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidFileName() {
        for (FileNameTest t : fileNameTests) {
            try {
                String ret = ESAPI.validator().SFDC_getValidFileName(t.inputStr, t.fileExtensions, t.allowNull);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input unless null if input was empty and that is allowed
                if (ret != null)
                    System.assert(ret.equals(t.inputStr), t.errText);
                else
                    System.assert(t.allowNull && (t.inputStr == null || t.inputStr.length() == 0), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }
    
    private class HttpRequestParamsTest {
        public String inputStr;
        public Set<String> requiredParams;
        public Set<String> optionalParams;
        public String errText;
        public Boolean expectedResult;
        
        public HttpRequestParamsTest(String inputStr, Set<String> requiredParams, Set<String> optionalParams, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.requiredParams = requiredParams;
            this.optionalParams = optionalParams;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final HttpRequestParamsTest [] httpRequestParamsTests = new HttpRequestParamsTest[]{};
    
    private static final Set<String> requiredParams1 = new Set<String>{'USER', 'PASS', 'PARAM1'};
    private static final Set<String> requiredParams2 = new Set<String>{'USER'};
    private static final Set<String> requiredParams3 = new Set<String>{};
    
    private static final Set<String> optionalParams1 = new Set<String>{'OPTUSER', 'OPTPASS', 'OPTPARAM1'};
    private static final Set<String> optionalParams2 = new Set<String>{'OPTUSER'};
    private static final Set<String> optionalParams3 = new Set<String>{};
    
    static {
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=def&PASS=jfg&PARAM1=ud847', requiredParams1, optionalParams1, 'Valid #1', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=def&PASS=jfg&PARAM1=ud847&OPTUSER=jhd6532', requiredParams1, optionalParams1, 'Valid #2', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=def&PASS=jfg&PARAM1=ud847&OPTUSER=jhd6532&OPTPASS=hdf&OPTPARAM1=g7345sfg', requiredParams1, optionalParams1, 'Valid #3', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=def&OPTUSER=123', requiredParams2, optionalParams1, 'Valid #4', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html', requiredParams3, optionalParams3, 'Valid #5', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html', requiredParams3, optionalParams1, 'Valid #6', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?', requiredParams3, optionalParams3, 'Valid #7', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?', requiredParams3, optionalParams1, 'Valid #8', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?OPTUSER=ksjfdhg', requiredParams3, optionalParams2, 'Valid #9', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?OPTUSER=ksjfdhg', requiredParams3, optionalParams1, 'Valid #10', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?OPTPARAM1=ksjfdhg', requiredParams3, optionalParams1, 'Valid #11', true));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?PASS=fdgg&USER=def&PARAM1=ud847', requiredParams1, optionalParams1, 'Valid #12', true));

        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?abc=def', requiredParams1, optionalParams1, 'Invalid #1', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=abc', requiredParams1, optionalParams1, 'Invalid #2', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=abc&PASS=gg', requiredParams1, optionalParams1, 'Invalid #3', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?PASS=gg&PARAM1=dfg', requiredParams1, optionalParams1, 'Invalid #4', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=abc&PARAM1=dfg', requiredParams1, optionalParams1, 'Invalid #5', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?user=abc&PASS=gg&PARAM1=dfg', requiredParams1, optionalParams1, 'Invalid #6', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?USER=abc&PASS=gg&PARAM1=dfg&extra=sdfgfg', requiredParams1, optionalParams1, 'Invalid #7', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?extra=sdfgfg&USER=abc&PASS=gg&PARAM1=dfg', requiredParams1, optionalParams1, 'Invalid #8', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?extra=sdfgfg&USER=abc&PASS=gg&PARAM1=dfg', null, optionalParams1, 'Invalid #9', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest('test.html?extra=sdfgfg&USER=abc&PASS=gg&PARAM1=dfg', requiredParams1, null, 'Invalid #10', false));
        httpRequestParamsTests.add(new HttpRequestParamsTest(null, requiredParams1, optionalParams1, 'Invalid #11', false));
    }

    static testMethod void testValidatorIsValidHttpRequestParams() {
        for (HttpRequestParamsTest t : httpRequestParamsTests) {
                PageReference pr = null;
                if (t.inputStr != null)
                    pr = new PageReference(t.inputStr);
            System.assertEquals(t.expectedResult, ESAPI.validator().isValidHTTPRequestParameterSet(pr, t.requiredParams, t.optionalParams), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidHttpRequestParams() {
        for (HttpRequestParamsTest t : httpRequestParamsTests) {
            try {
                PageReference pr = null;
                if (t.inputStr != null)
                    pr = new PageReference(t.inputStr);
                ESAPI.validator().assertValidHTTPRequestParameterSet(pr, t.requiredParams, t.optionalParams);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }

    private class RedirectDefaultDomainTest {
        public String inputStr;
        public String errText;
        public Boolean expectedResult;
        
        public RedirectDefaultDomainTest(String inputStr, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final RedirectDefaultDomainTest [] redirectDefaultDomainTests = new RedirectDefaultDomainTest[]{};
    
    static {
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/test.html', 'Valid #1', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/test.html?', 'Valid #2', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/test.html?USER=def', 'Valid #3', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://na7.salesforce.com/test.html?USER=def&OPTUSER=123', 'Valid #4', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://na7.salesforce.com/test.html', 'Valid #5', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://na7.salesforce.com', 'Valid #6', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://na7.salesforce.com', 'Valid #7', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://na7.salesforce.com/', 'Valid #8', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://na7.salesforce.com/', 'Valid #9', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://na7.salesforce.com/www.google.com', 'Valid #10', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://na7.salesforce.com/www.google.com', 'Valid #11', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://kjfhfg.salesforce.com/www.google.com', 'Valid #12', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://le4t98whw.salesforce.com/www.google.com', 'Valid #13', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/javascript%3Atest', 'Valid #14', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/http%3A//na1.salesforce.com', 'Valid #15', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/http%3a//www.google.com', 'Valid #16', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforce.com/', 'Valid #18', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://sdfgdfgfsdg.c.na7.salesforce.com/', 'Valid #19', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/%D7%A9', 'Valid #20', true));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforce.com/apex/testPage?id=8435987435987435&value=1&param=2', 'Valid #21', true));

        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('test.html?abc=def', 'Invalid #1', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('test.html', 'Invalid #2', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('www.salesforce.com', 'Invalid #3', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('www.google.com', 'Invalid #4', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('na7.salesforce.com', 'Invalid #5', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('javascript:eval', 'Invalid #6', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest(null, 'Invalid #7', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('', 'Invalid #8', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('http://na7.salesforce.com/'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789', 'Invalid #9', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforce.com.c/', 'Invalid #10', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforce.comc/', 'Invalid #11', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforcec.com/', 'Invalid #12', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://c.na7.salesforcecom/', 'Invalid #13', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https:///', 'Invalid #14', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://.salesforce.com/', 'Invalid #15', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://salesforce.com/', 'Invalid #16', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789.salesforce.com/', 'Invalid #17', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/javascript:test', 'Invalid #18', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/javascript%GGtest', 'Invalid #19', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/' + EncodingUtil.urlDecode('%D7%A9', 'UTF-8'), 'Invalid #20', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('/' + EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 'Invalid #21', false));
        redirectDefaultDomainTests.add(new RedirectDefaultDomainTest('https://na1.salesforce.com/' + EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 'Invalid #22', false));
    }

    static testMethod void testValidatorIsValidRedirectDefaultDomain() {
        PageReference pr = new PageReference('https://c.na7.salesforce.com');
        pr.getHeaders().put('Host', 'c.na7.salesforce.com');
        Test.setCurrentPage(pr);
        
        for (RedirectDefaultDomainTest t : redirectDefaultDomainTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().SFDC_isValidRedirectLocation(t.inputStr), t.errText);
        }
    }
    
    static testMethod void testValidatorGetValidRedirectDefaultDomain() {
        PageReference pr = new PageReference('https://c.na7.salesforce.com');
        pr.getHeaders().put('Host', 'c.na7.salesforce.com');
        Test.setCurrentPage(pr);
        
        for (RedirectDefaultDomainTest t : redirectDefaultDomainTests) {
            try {
                String ret = ESAPI.validator().SFDC_getValidRedirectLocation(t.inputStr);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.inputStr), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }
    
    private class RedirectTest {
        public String inputStr;
        public String currentDomain;
        public String errText;
        public Boolean expectedResult;
        
        public RedirectTest(String inputStr, String currentDomain, String errText, Boolean expectedResult) {
            this.inputStr = inputStr;
            this.currentDomain = currentDomain;
            this.errText = errText;
            this.expectedResult = expectedResult;
        }
    }
    
    private static final RedirectTest [] redirectTests = new RedirectTest[]{};
    
    static {
        redirectTests.add(new RedirectTest('/test.html', 'na7.salesforce.com', 'Valid #1', true));
        redirectTests.add(new RedirectTest('/test.html?', 'na7.salesforce.com', 'Valid #2', true));
        redirectTests.add(new RedirectTest('/test.html?USER=def', 'na7.salesforce.com', 'Valid #3', true));
        redirectTests.add(new RedirectTest('https://na7.salesforce.com/test.html?USER=def&OPTUSER=123', 'na7.salesforce.com', 'Valid #4', true));
        redirectTests.add(new RedirectTest('http://na7.salesforce.com/test.html', 'na7.salesforce.com', 'Valid #5', true));
        redirectTests.add(new RedirectTest('https://na7.salesforce.com', 'na7.salesforce.com', 'Valid #6', true));
        redirectTests.add(new RedirectTest('http://na7.salesforce.com', 'na7.salesforce.com', 'Valid #7', true));
        redirectTests.add(new RedirectTest('https://na7.salesforce.com/', 'na7.salesforce.com', 'Valid #8', true));
        redirectTests.add(new RedirectTest('http://na7.salesforce.com/', 'na7.salesforce.com', 'Valid #9', true));
        redirectTests.add(new RedirectTest('https://na7.salesforce.com/www.google.com', 'na7.salesforce.com', 'Valid #10', true));
        redirectTests.add(new RedirectTest('http://na7.salesforce.com/www.google.com', 'na7.salesforce.com', 'Valid #11', true));
        redirectTests.add(new RedirectTest('/javascript%3Atest', 'na7.salesforce.com', 'Valid #12', true));
        redirectTests.add(new RedirectTest('/http%3A//na1.salesforce.com', 'na7.salesforce.com', 'Valid #13', true));
        redirectTests.add(new RedirectTest('/http%3a//www.google.com', 'na7.salesforce.com', 'Valid #14', true));
        redirectTests.add(new RedirectTest('https://c.na7.salesforce.com/', 'c.na7.salesforce.com', 'Valid #16', true));
        redirectTests.add(new RedirectTest('https://sdfgdfgfsdg.c.na7.salesforce.com/', 'sdfgdfgfsdg.c.na7.salesforce.com', 'Valid #17', true));
        redirectTests.add(new RedirectTest('/%D7%A9', 'na7.salesforce.com', 'Valid #18', true));
        redirectTests.add(new RedirectTest('https://c.na7.salesforce.com/apex/testPage?id=8435987435987435&value=1&param=2', 'c.na7.salesforce.com', 'Valid #19', true));
        redirectTests.add(new RedirectTest('https://www.google.com/', 'www.google.com', 'Valid #20', true));
        redirectTests.add(new RedirectTest('https://1.2.google.com/', '1.2.google.com', 'Valid #21', true));
        redirectTests.add(new RedirectTest('https://na1.salesforce.com/', 'www.google.com', 'Valid #22', true));

        redirectTests.add(new RedirectTest('test.html?abc=def', 'na7.salesforce.com', 'Invalid #1', false));
        redirectTests.add(new RedirectTest('test.html', 'na7.salesforce.com', 'Invalid #2', false));
        redirectTests.add(new RedirectTest('www.salesforce.com', 'www.salesforce.com', 'Invalid #3', false));
        redirectTests.add(new RedirectTest('www.google.com', 'www.google.com', 'Invalid #4', false));
        redirectTests.add(new RedirectTest('na7.salesforce.com', 'na7.salesforce.com', 'Invalid #5', false));
        redirectTests.add(new RedirectTest('javascript:eval', 'na7.salesforce.com', 'Invalid #6', false));
        redirectTests.add(new RedirectTest(null, 'na7.salesforce.com', 'Invalid #7', false));
        redirectTests.add(new RedirectTest('', 'na7.salesforce.com', 'Invalid #8', false));
        redirectTests.add(new RedirectTest('http://na7.salesforce.com/'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789'
            + '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789', 'na7.salesforce.com', 'Invalid #9', false));
        redirectTests.add(new RedirectTest('https://c.na7.salesforce.com.c/', 'c.na7.salesforce.com', 'Invalid #10', false));
        redirectTests.add(new RedirectTest('https://c.na7.salesforce.comc/', 'c.na7.salesforce.com', 'Invalid #11', false));
        redirectTests.add(new RedirectTest('https://c.na7.salesforcec.com/', 'c.na7.salesforce.com', 'Invalid #12', false));
        redirectTests.add(new RedirectTest('https://c.na7.salesforcecom/', 'c.na7.salesforce.com', 'Invalid #13', false));
        redirectTests.add(new RedirectTest('https:///', 'na7.salesforce.com', 'Invalid #14', false));
        redirectTests.add(new RedirectTest('https://.salesforce.com/', 'salesforce.com', 'Invalid #15', false));
        redirectTests.add(new RedirectTest('https://0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789.salesforce.com/', 'salesforce.com', 'Invalid #16', false));
        redirectTests.add(new RedirectTest('/javascript:test', 'c.na7.salesforce.com', 'Invalid #17', false));
        redirectTests.add(new RedirectTest('/javascript%GGtest', 'c.na7.salesforce.com', 'Invalid #18', false));
        redirectTests.add(new RedirectTest('/' + EncodingUtil.urlDecode('%D7%A9', 'UTF-8'), 'c.na7.salesforce.com', 'Invalid #19', false));
        redirectTests.add(new RedirectTest('/' + EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 'c.na7.salesforce.com', 'Invalid #20', false));
        redirectTests.add(new RedirectTest('https://na1.salesforce.com/' + EncodingUtil.urlDecode('%C2%80', 'UTF-8'), 'na1.salesforce.com', 'Invalid #21', false));
        redirectTests.add(new RedirectTest('https://c.na7.salesforcecom/', null, 'Invalid #22', false));
        redirectTests.add(new RedirectTest('https://www.google.com/', 'login.google.com', 'Invalid #23', false));
        redirectTests.add(new RedirectTest('https://1.2.google.com/', '', 'Invalid #24', false));
        redirectTests.add(new RedirectTest('https:///', '', 'Invalid #25', false));
        redirectTests.add(new RedirectTest('https://abc/', 'abc', 'Invalid #26', false));
    }

    static testMethod void testValidatorIsValidRedirect() {
        for (RedirectTest t : redirectTests) {
            System.assertEquals(t.expectedResult, ESAPI.validator().SFDC_isValidRedirectLocation(t.inputStr, t.currentDomain), t.errText);
        }
    }

    static testMethod void testValidatorGetValidRedirect() {
        for (RedirectTest t : redirectTests) {
            try {
                String ret = ESAPI.validator().SFDC_getValidRedirectLocation(t.inputStr, t.currentDomain);
                // if no exception - check if we are expecting a valid test
                System.assert(t.expectedResult == true, t.errText);
                // also make sure return value is equal to input
                System.assert(ret.equals(t.inputStr), t.errText);
            } catch (Exception e) {
                // if exception - check if we are expecting an invalid test
                System.assert(t.expectedResult == false, t.errText);
            }
        }
    }    
}