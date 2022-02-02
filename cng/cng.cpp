#define FAKE(x) void* x() { return #x; }
FAKE(BCryptAddContextFunctionProvider_FAKE)
FAKE(BCryptCloseAlgorithmProvider_FAKE)
FAKE(BCryptCreateHash_FAKE)
FAKE(BCryptCreateMultiHash_FAKE)
FAKE(BCryptDecrypt_FAKE)
FAKE(BCryptDeriveKey_FAKE)
FAKE(BCryptDeriveKeyCapi_FAKE)
FAKE(BCryptDeriveKeyPBKDF2_FAKE)
FAKE(BCryptDestroyHash_FAKE)
FAKE(BCryptDestroyKey_FAKE)
FAKE(BCryptDestroySecret_FAKE)
FAKE(BCryptDuplicateHash_FAKE)
FAKE(BCryptDuplicateKey_FAKE)
FAKE(BCryptEncrypt_FAKE)
FAKE(BCryptEnumAlgorithms_FAKE)
FAKE(BCryptEnumProviders_FAKE)
FAKE(BCryptExportKey_FAKE)
FAKE(BCryptFinalizeKeyPair_FAKE)
FAKE(BCryptFinishHash_FAKE)
FAKE(BCryptFreeBuffer_FAKE)
FAKE(BCryptGenRandom_FAKE)
FAKE(BCryptGenerateKeyPair_FAKE)
FAKE(BCryptGenerateSymmetricKey_FAKE)
FAKE(BCryptGetFipsAlgorithmMode_FAKE)
FAKE(BCryptGetProperty_FAKE)
FAKE(BCryptHash_FAKE)
FAKE(BCryptHashData_FAKE)
FAKE(BCryptImportKey_FAKE)
FAKE(BCryptImportKeyPair_FAKE)
FAKE(BCryptKeyDerivation_FAKE)
FAKE(BCryptOpenAlgorithmProvider_FAKE)
FAKE(BCryptProcessMultiOperations_FAKE)
FAKE(BCryptRegisterConfigChangeNotify_FAKE)
FAKE(BCryptRegisterProvider_FAKE)
FAKE(BCryptResolveProviders_FAKE)
FAKE(BCryptSecretAgreement_FAKE)
FAKE(BCryptSetProperty_FAKE)
FAKE(BCryptSignHash_FAKE)
FAKE(BCryptUnregisterConfigChangeNotify_FAKE)
FAKE(BCryptUnregisterProvider_FAKE)
FAKE(BCryptVerifySignature_FAKE)
FAKE(CngGetFipsAlgorithmMode_FAKE)
FAKE(EntropyPoolTriggerReseedForIum_FAKE)
FAKE(EntropyProvideData_FAKE)
FAKE(EntropyRegisterCallback_FAKE)
FAKE(EntropyRegisterSource_FAKE)
FAKE(EntropyUnregisterSource_FAKE)
FAKE(SslDecrementProviderReferenceCount_FAKE)
FAKE(SslDecryptPacket_FAKE)
FAKE(SslEncryptPacket_FAKE)
FAKE(SslExportKey_FAKE)
FAKE(SslExportKeyingMaterial_FAKE)
FAKE(SslFreeObject_FAKE)
FAKE(SslImportKey_FAKE)
FAKE(SslIncrementProviderReferenceCount_FAKE)
FAKE(SslLookupCipherLengths_FAKE)
FAKE(SslLookupCipherSuiteInfo_FAKE)
FAKE(SslOpenProvider_FAKE)
FAKE(SymCrypt802_11SaeCustomCommitCreate_FAKE)
FAKE(SymCrypt802_11SaeCustomCommitProcess_FAKE)
FAKE(SymCrypt802_11SaeCustomDestroy_FAKE)
FAKE(SymCrypt802_11SaeCustomInit_FAKE)
FAKE(SystemPrng_FAKE)