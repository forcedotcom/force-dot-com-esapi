== v1.7 ===
Notable API Changes:
 -  The SFDCAccessController.fieldsToStringSetMaintainCase method has been changed from public to private to allow implementation changes as needed by the ESAPI library.
 - CRUD violations are bubbled up from Security.stripInaccessible as Apex system exception types, rather than the custom SFDCAccessControlException type.
