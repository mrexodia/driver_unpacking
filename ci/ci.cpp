#define FAKE(x) void* x() { return #x; }
FAKE(noname1)
FAKE(noname2)
FAKE(noname3)
FAKE(CiCheckSignedFile_FAKE)
FAKE(CiFindPageHashesInCatalog_FAKE)
FAKE(CiFindPageHashesInSignedFile_FAKE)
FAKE(CiFreePolicyInfo_FAKE)
FAKE(CiGetCertPublisherName_FAKE)
FAKE(CiGetPEInformation_FAKE)
FAKE(CiInitialize_FAKE)
FAKE(CiSetTrustedOriginClaimId_FAKE)
FAKE(CiValidateFileObject_FAKE)
FAKE(CiVerifyHashInCatalog_FAKE)
