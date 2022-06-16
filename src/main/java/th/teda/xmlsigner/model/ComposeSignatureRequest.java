package th.teda.xmlsigner.model;

public class ComposeSignatureRequest {

    private String signatureId;
    private String signatureValue;
    private String signedInfo;
    private String xadesSignedProperties;
    private String signerCert;

    public ComposeSignatureRequest(){

    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public String getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(String signatureValue) {
        this.signatureValue = signatureValue;
    }

    public String getSignedInfo() {
        return signedInfo;
    }

    public void setSignedInfo(String signedInfo) {
        this.signedInfo = signedInfo;
    }

    public String getXadesSignedProperties() {
        return xadesSignedProperties;
    }

    public void setXadesSignedProperties(String xadesSignedProperties) {
        this.xadesSignedProperties = xadesSignedProperties;
    }

    public String getSignerCert() {
        return signerCert;
    }

    public void setSignerCert(String signerCert) {
        this.signerCert = signerCert;
    }

}
