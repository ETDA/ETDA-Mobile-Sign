package th.teda.xmlsigner.model;

public class DigestDocRequest {

    private String inputFile;
    private String digestMethod;

    public DigestDocRequest(){

    }

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public String getDigestMethod() {
        return digestMethod;
    }

    public void setDigestMethod(String digestMethod) {
        this.digestMethod = digestMethod;
    }

}
