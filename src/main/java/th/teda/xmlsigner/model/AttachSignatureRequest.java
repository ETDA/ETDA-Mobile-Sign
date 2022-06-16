package th.teda.xmlsigner.model;

public class AttachSignatureRequest {

    private String inputFile;
    private String signature;

    public AttachSignatureRequest(){

    }

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

}
