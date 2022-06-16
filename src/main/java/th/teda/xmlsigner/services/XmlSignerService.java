package th.teda.xmlsigner.services;

import th.teda.xmlsigner.model.AttachSignatureRequest;
import th.teda.xmlsigner.model.AttachSignatureResponse;
import th.teda.xmlsigner.model.ComposeSignatureRequest;
import th.teda.xmlsigner.model.ComposeSignatureResponse;
import th.teda.xmlsigner.model.CreateSignedInfoRequest;
import th.teda.xmlsigner.model.CreateSignedInfoResponse;
import th.teda.xmlsigner.model.DigestDocRequest;
import th.teda.xmlsigner.model.DigestDocResponse;
import th.teda.xmlsigner.model.ReloadResponse;

public interface XmlSignerService {

    Boolean verifyDigestDocInput(DigestDocRequest request) throws Exception;
    DigestDocResponse digestDoc(DigestDocRequest request) throws Exception;
    Boolean verifyCreateSignedInfoInput(CreateSignedInfoRequest request) throws Exception;
    CreateSignedInfoResponse createSignedInfo(CreateSignedInfoRequest request) throws Exception;
    Boolean verifyComposeSignatureInput(ComposeSignatureRequest request) throws Exception;
    ComposeSignatureResponse composeSignature(ComposeSignatureRequest request) throws Exception;
    Boolean verifyAttachSignatureInput(AttachSignatureRequest request) throws Exception;
    AttachSignatureResponse attachSignature(AttachSignatureRequest request) throws Exception;
    ReloadResponse reloadConfig() throws Exception;
}
