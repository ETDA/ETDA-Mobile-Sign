package th.teda.xmlsigner.configurations;

public class Constants {
	public static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
	public static final String XADES141_NS = "http://uri.etsi.org/01903/v1.4.1#";
	public static final String SIGNED_PROPS_TYPE_URI = "http://uri.etsi.org/01903#SignedProperties";
	public static final String METHOD_DIGEST_DOC = "digestDoc";
	public static final String METHOD_CREATE_SIGNEDINFO = "createSignedInfo";
	public static final String METHOD_COMPOSE_SIGNATURE = "composeSignature";
	public static final String METHOD_ATTACH_SIGNATURE = "attachSignature";
	public static final String LABEL_STATUS = "status";
	public static final String LABEL_DESCRIPTION = "description";
	public static final String LABEL_DESCRIPTION_ERROR = "Error : ";
	public static final String LABEL_DIGEST = "digest";
	public static final String LABEL_NAMESPACE = "namespace";
	public static final String LABEL_SIGNATURE_ID = "signatureId";
	public static final String LABEL_SIGNEDINFO = "signedInfo";
	public static final String LABEL_SIGNEDINFO_DIGEST = "signedInfoDigest";
	public static final String LABEL_XADESSIGNEDPROPERTIES = "xadesSignedProperties";
	public static final String LABEL_SIGNATURE = "signature";
	public static final String LABEL_OUTPUT_FILE = "outputFile";

	public static final String CODE_CERT_FORMAT_INVALID = "error.message.certFormatInvalid";
	public static final String CODE_CDP_NOT_FOUND = "error.message.cdpNotFound";
	public static final String CODE_CERT_REVOKED = "error.message.revoked";
	public static final String CODE_DIGEST_ALGO_NOT_SUPPORTED = "error.message.digestAlgorithmNotSupported";
	public static final String CODE_SIGNATURE_ALGO_NOT_SUPPORTED = "error.message.signatureAlgorithmNotSupported";
	public static final String CODE_METHOD_NOT_SUPPORTED = "error.message.methodNotSupported";
	public static final String CODE_OCSP_CRL_CONNECTION_ERROR = "warning.message.ocspCrlConnectionError";
	public static final String DEFAULT_DIGEST_ALGO = "default.digestAlgorithm";
	public static final String DEFAULT_SIGNATURE_ALGO = "default.signatureAlgorithm";	

	private Constants() {}
}
