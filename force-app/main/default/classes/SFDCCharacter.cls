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
 * This class adds basic character functionality to the Apex language. We need this because in Apex we don't have access to the bytes and byte arrays.
 * It uses two maps that link between the integer value and the string representation of each character.
 */
global class SFDCCharacter {
	
	/**
 	* This is the SFDCInvalidCharacterException class. It does not add any functionality to the generic Exception class.
 	* However, in Apex we must extend the Exception class before using it. 
 	*/
	public with sharing class SFDCInvalidCharacterException extends Exception{	}

	private static final Map<String,Integer> strToInt = new Map<String,Integer>();
	private static final Map<Integer,String> intToStr = new Map<Integer,String>();
	
	private Integer valInt = 0;
	private String valStr = null;
	
	private SFDCCharacter() {
		// this will not allow using the default constructor		
	}

	global SFDCCharacter(Integer x) {
		valStr = toStr(x);
		valInt = x;
	}

	global SFDCCharacter(String x) {
		valInt = toInt(x);
		valStr = x;
	}
	
	global void updateVal(Integer x) {
		valStr = toStr(x);
		valInt = x;
	}

	global void updateVal(String x) {
		valInt = toInt(x);
		valStr = x;
	}
	
	global static String toStr(Integer x) {
		if(intToStr.containsKey(x) == false)
			// be carefull not to throw any user input value that might cause XSS if the developer will not catch and escape
			throw new SFDCInvalidCharacterException('Invalid charcter integer');
		return intToStr.get(x);
	}

	global static Integer toInt(String x) {
		if(SFDCStringUtils.isEmpty(x))
			throw new SFDCInvalidCharacterException('Invalid charcter string empty string');

		if(strToInt.containsKey(x) == false)
			// be carefull not to throw any user input value that might cause XSS if the developer will not catch and escape
			throw new SFDCInvalidCharacterException('Invalid charcter string');
		return strToInt.get(x);
	}

	global String toStr(){
		return valStr;
	}
	
	global Integer toInt(){
		return valInt;
	}
	
	global Boolean equals(SFDCCharacter x) {
		return valInt == x.toInt();
	}
	
	static {
		strToInt.put(null, 0);
		strToInt.put('\t', 9);
		strToInt.put('\n', 10);
		strToInt.put('\f', 12);
		strToInt.put('\r', 13);
		strToInt.put(' ', 32);
		strToInt.put('!', 33);
		strToInt.put('"', 34);
		strToInt.put('#', 35);
		strToInt.put('$', 36);
		strToInt.put('%', 37);
		strToInt.put('&', 38);
		strToInt.put('\'', 39);
		strToInt.put('(', 40);
		strToInt.put(')', 41);
		strToInt.put('*', 42);
		strToInt.put('+', 43);
		strToInt.put(',', 44);
		strToInt.put('-', 45);
		strToInt.put('.', 46);
		strToInt.put('/', 47);
		strToInt.put('0', 48);
		strToInt.put('1', 49);
		strToInt.put('2', 50);
		strToInt.put('3', 51);
		strToInt.put('4', 52);
		strToInt.put('5', 53);
		strToInt.put('6', 54);
		strToInt.put('7', 55);
		strToInt.put('8', 56);
		strToInt.put('9', 57);
		strToInt.put(':', 58);
		strToInt.put(';', 59);
		strToInt.put('<', 60);
		strToInt.put('=', 61);
		strToInt.put('>', 62);
		strToInt.put('?', 63);
		strToInt.put('@', 64);
		strToInt.put('A', 65);
		strToInt.put('B', 66);
		strToInt.put('C', 67);
		strToInt.put('D', 68);
		strToInt.put('E', 69);
		strToInt.put('F', 70);
		strToInt.put('G', 71);
		strToInt.put('H', 72);
		strToInt.put('I', 73);
		strToInt.put('J', 74);
		strToInt.put('K', 75);
		strToInt.put('L', 76);
		strToInt.put('M', 77);
		strToInt.put('N', 78);
		strToInt.put('O', 79);
		strToInt.put('P', 80);
		strToInt.put('Q', 81);
		strToInt.put('R', 82);
		strToInt.put('S', 83);
		strToInt.put('T', 84);
		strToInt.put('U', 85);
		strToInt.put('V', 86);
		strToInt.put('W', 87);
		strToInt.put('X', 88);
		strToInt.put('Y', 89);
		strToInt.put('Z', 90);
		strToInt.put('[', 91);
		strToInt.put('\\', 92);
		strToInt.put(']', 93);
		strToInt.put('^', 94);
		strToInt.put('_', 95);
		strToInt.put('`', 96);
		strToInt.put('a', 97);
		strToInt.put('b', 98);
		strToInt.put('c', 99);
		strToInt.put('d', 100);
		strToInt.put('e', 101);
		strToInt.put('f', 102);
		strToInt.put('g', 103);
		strToInt.put('h', 104);
		strToInt.put('i', 105);
		strToInt.put('j', 106);
		strToInt.put('k', 107);
		strToInt.put('l', 108);
		strToInt.put('m', 109);
		strToInt.put('n', 110);
		strToInt.put('o', 111);
		strToInt.put('p', 112);
		strToInt.put('q', 113);
		strToInt.put('r', 114);
		strToInt.put('s', 115);
		strToInt.put('t', 116);
		strToInt.put('u', 117);
		strToInt.put('v', 118);
		strToInt.put('w', 119);
		strToInt.put('x', 120);
		strToInt.put('y', 121);
		strToInt.put('z', 122);
		strToInt.put('{', 123);
		strToInt.put('|', 124);
		strToInt.put('}', 125);
		strToInt.put('~', 126);

		for(String key : strToInt.keySet()) {
			intToStr.put(strToInt.get(key), key);
		}
	}
}