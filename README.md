# Getting started with Force.com ESAPI

## Overview
This page is intended to give a basic understanding of how to use the Force.com ESAPI library. 
This library is published by Salesforce.com under the New BSD license. 
You should read and accept the license before you use, modify, and/or redistribute this software.

Follow the steps below to get started. For more detailed documentation on this library, please refer to the doc folder.

### Steps
1. Download the latest release from the download page.
2. Make any modifications in the code if you need additional functionality not covered by the library.
3. Upload the classes to your Force.com Org.
4. Start using it in your other classes.

### Package Installation

- Go to the <a href="https://github.com/forcedotcom/force-dot-com-esapi/releases">releases</a> section to get the installation link for both managed and un-managed versions of the ESAPI package.

## Example Code

### Input Validation:

The Validator module defines a set of methods for validating untrusted input. This allows server side validation in apex.

Example using exceptions (the get... function will throw an exception if fail, and return the input if no error has occurred):

```Java
String creditCard = ApexPages.currentPage().getParameters().get('creditcard');
try {
    creditCard = ESAPI.validator().getValidCreditCard(creditCard, false);
} catch (Exception e) {
    /*
    report error here using e.getMessage(). Make sure you escape the string before
    displaying it back on page, and also be careful not to expose any internal information.
    */
}
```
Example using return value (the is... function will never throw exceptions, instead it will return false in case of error):

```Java
String creditCard = ApexPages.currentPage().getParameters().get('creditcard');
if (ESAPI.validator().isValidCreditCard(creditCard, false) == false)
    // do something here
```

### Output Encoding

The Encoder module contains a number of methods for encoding output so that it will be safe for display in visual force pages. 
These functions are equivalent to the visual force JSENCODE, HTMLENCODE, JSINHTMLENCODE and URLENCODE functions.

```Java
String usertext = ApexPages.currentPage().getParameters().get('usertext');
// the next line encodes the usertext similar to the VisualForce HTMLENCODE function but within an Apex class.
usertext = ESAPI.encoder().SFDC_HTMLENCODE(usertext);
```

### Access Control
The access control module provides functionality to enforce the Force.com built in access control mechanisms: CRUD, FLS, and Sharing. As described in the apex documentation, apex classes execute in system context and not in the current user context. This is why the platform can't enforce any of the security models. For more details please see <a href="https://developer.salesforce.com/page/Enforcing_CRUD_and_FLS">Enforcing CRUD and FLS</a>.
This ESAPI module allows apex classes execute statements such as insert object; as if operating in user context.

For example, if we want to update an object in user context, enforcing sharing rules as well as CRUD and FLS we will use the module in this way:

```Java
// s is a modified SObject

try {
    ESAPI.accessController().setSharingMode(SFDCAccessController.SharingMode.WITH);
    ESAPI.accessController().updateAsUser(s, new List<String>{'data'});
} catch (SFDCAccessControlException e) {
    message = 'Access Control violation - Type: ' + e.getExceptionType() + ' Reason: ' 
        + e.getExceptionReason() + ' Object: ' + e.getExceptionObject() + ' Field: ' 
        + e.getExceptionField() + ' Text: ' + e.getText();
}
```

You can use Access Control also to check which objects fields the current user can read/update etc before presenting the page and not just on the insert/update/delete operation.
