package th.teda.xmlsigner.model;

public class CreateSignedInfoRequest {

    private String signerCert;
    private String issuerCert;
    private String namespace;
    private String digest;
    private String digestMethod;
    private String signatureMethod;

    public CreateSignedInfoRequest(){

    }

    public String getSignerCert() {
        return signerCert;
    }

    public void setSignerCert(String signerCert) {
        this.signerCert = signerCert;
    }

    public String getIssuerCert() {
        return issuerCert;
    }

    public void setIssuerCert(String issuerCert) {
        this.issuerCert = issuerCert;
    }

    public String getNamespace() {
        return namespace;
    }

    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getDigestMethod() {
        return digestMethod;
    }

    public void setDigestMethod(String digestMethod) {
        this.digestMethod = digestMethod;
    }

    public String getSignatureMethod() {
        return signatureMethod;
    }

    public void setSignatureMethod(String signatureMethod) {
        this.signatureMethod = signatureMethod;
    }

}
