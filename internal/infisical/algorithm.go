package infisical

// Signing algorithm identifiers accepted by the Infisical sign endpoint. These are the exact
// strings the API expects; the CNG layer maps Windows padding + hash + key type onto them.
const (
	AlgRSAPKCS1SHA256 = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgRSAPKCS1SHA384 = "RSASSA_PKCS1_V1_5_SHA_384"
	AlgRSAPKCS1SHA512 = "RSASSA_PKCS1_V1_5_SHA_512"
	AlgRSAPSSSHA256   = "RSASSA_PSS_SHA_256"
	AlgRSAPSSSHA384   = "RSASSA_PSS_SHA_384"
	AlgRSAPSSSHA512   = "RSASSA_PSS_SHA_512"
	AlgECDSASHA256    = "ECDSA_SHA_256"
	AlgECDSASHA384    = "ECDSA_SHA_384"
	AlgECDSASHA512    = "ECDSA_SHA_512"
)
