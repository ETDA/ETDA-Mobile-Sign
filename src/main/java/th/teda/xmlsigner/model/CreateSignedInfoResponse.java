package th.teda.xmlsigner.model;

public class CreateSignedInfoResponse {

    private String description;
    private String status;
    private String signatureId;
    private String signedInfo;
    private String xadesSignedProperties;
    private String signedInfoDigest;

    public CreateSignedInfoResponse(){

    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
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

    public String getSignedInfoDigest() {
        return signedInfoDigest;
    }

    public void setSignedInfoDigest(String signedInfoDigest) {
        this.signedInfoDigest = signedInfoDigest;
    }

}
