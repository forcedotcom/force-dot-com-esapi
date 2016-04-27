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
 * @author Sébastien Colladon (scolladon .at. salesforce.com) <a href="http://www.salesforce.com">Salesforce.com</a>
 * @created 2016
 */

/**
 * This class is a basic decoder.
 */
global with sharing class SFDCDecoder {


    /**
     * Note : This function always decodes a base64 url encoded string<br><br>
     *
     * Example:<br>
     * <PRE>
     * //htmlstr is going to be converted from url to blob
     * htmlstr = ESAPI.decoder().SFDC_BASE64_URLDECODE(base64urlencodedText);
     * </PRE>
     */
    global Blob SFDC_BASE64_URLDECODE(final String input){
        if(String.isBlank(input)) {
            return null;
        }

        return EncodingUtil.base64Decode(input.replace('-', '+')
                .replace('_', '/')
                .rightPad(math.mod(input.length() + (math.mod(4 - input.length(), 4)), 4))
                .replace(' ','='));
    }
}