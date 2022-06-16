package th.teda.xmlsigner.controller;


import th.teda.xmlsigner.services.XmlSignerService;
import th.teda.xmlsigner.model.AttachSignatureRequest;
import th.teda.xmlsigner.model.AttachSignatureResponse;
import th.teda.xmlsigner.model.ComposeSignatureRequest;
import th.teda.xmlsigner.model.ComposeSignatureResponse;
import th.teda.xmlsigner.model.CreateSignedInfoRequest;
import th.teda.xmlsigner.model.CreateSignedInfoResponse;
import th.teda.xmlsigner.model.DigestDocRequest;
import th.teda.xmlsigner.model.DigestDocResponse;
import th.teda.xmlsigner.model.ReloadResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

//import java.util.concurrent.CompletableFuture;

import static th.teda.xmlsigner.results.Results.*;

@Component
@RestController
@RequestMapping("xmlSigner/v1")
public class XmlSignerController {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    XmlSignerService xmlSignerService;

    @RequestMapping(value = "/digestDoc", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<DigestDocResponse> xmlSignerDigestDocRequest(@RequestBody DigestDocRequest request) throws Exception {
        DigestDocResponse resController = new DigestDocResponse();

        try {

            logger.debug("************Start XmlSigner DigestDoc session()************");

            //InputVerify
            Boolean validInput = xmlSignerService.verifyDigestDocInput(request);
            if (!validInput) {
                logger.error("[digestDoc][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[xmlSigner]: DigestDoc ResultCode: " + resController.getStatus());
                logger.debug("*******************End XmlSigner DigestDoc session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //DigestDoc
            resController = xmlSignerService.digestDoc(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[xmlSigner]: DigestDoc ResultCode: " + resController.getStatus());
            logger.debug("*******************End XmlSigner DigestDoc session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[xmlSigner]: DigestDoc ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }
    
    @RequestMapping(value = "/createSignedInfo", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<CreateSignedInfoResponse> xmlSignerCreateSignedInfoRequest(@RequestBody CreateSignedInfoRequest request) throws Exception {
        CreateSignedInfoResponse resController = new CreateSignedInfoResponse();

        try {

            logger.debug("************Start XmlSigner CreateSignedInfo session()************");

            //InputVerify
            Boolean validInput = xmlSignerService.verifyCreateSignedInfoInput(request);
            if (!validInput) {
                logger.error("[createSignedInfo][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[xmlSigner]: CreateSignedInfo ResultCode: " + resController.getStatus());
                logger.debug("*******************End XmlSigner CreateSignedInfo session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //CreateSignInfo
            resController = xmlSignerService.createSignedInfo(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[xmlSigner]: CreateSignedInfo ResultCode: " + resController.getStatus());
            logger.debug("*******************End XmlSigner CreateSignedInfo session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[xmlSigner]: CreateSignedInfo ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/composeSignature", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<ComposeSignatureResponse> xmlSignerComposeSignatureRequest(@RequestBody ComposeSignatureRequest request) throws Exception {
        ComposeSignatureResponse resController = new ComposeSignatureResponse();

        try {

            logger.debug("************Start XmlSigner ComposeSignature session()************");

            //InputVerify
            Boolean validInput = xmlSignerService.verifyComposeSignatureInput(request);
            if (!validInput) {
                logger.error("[composeSignature][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[xmlSigner]: ComposeSignature ResultCode: " + resController.getStatus());
                logger.debug("*******************End XmlSigner ComposeSignature session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //ComposeSignature
            resController = xmlSignerService.composeSignature(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[xmlSigner]: ComposeSignature ResultCode: " + resController.getStatus());
            logger.debug("*******************End XmlSigner CompposeSignature session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[xmlSigner]: ComposeSignature ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/attachSignature", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<AttachSignatureResponse> xmlSignerAttachSignatureRequest(@RequestBody AttachSignatureRequest request) throws Exception {
        AttachSignatureResponse resController = new AttachSignatureResponse();

        try {

            logger.debug("************Start XmlSigner AttachSignature session()************");

            //InputVerify
            Boolean validInput = xmlSignerService.verifyAttachSignatureInput(request);
            if (!validInput) {
                logger.error("[attachSignature][Verify Input]: Verify Input FAILED");
            	resController.setDescription("Error : " + "[Verify Input]: Verify Input FAILED");
                resController.setStatus(FAILED_STATUS);
                logger.info("[xmlSigner]: AttachSignature ResultCode: " + resController.getStatus());
                logger.debug("*******************End XmlSigner AttachSignature session()********************");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(resController);
            }

            //AttachSignature
            resController = xmlSignerService.attachSignature(request);
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[xmlSigner]: AttachSignature ResultCode: " + resController.getStatus());
            logger.debug("*******************End XmlSigner AttachSignature session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[xmlSigner]: AttachSignature ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

    @RequestMapping(value = "/reload", method = RequestMethod.POST, produces = "application/json")
    public ResponseEntity<ReloadResponse> xmlSignerReloadRequest() throws Exception {
        ReloadResponse resController = new ReloadResponse();

        try {

            logger.debug("************Start XmlSigner Reload session()************");

            //Reload configuration
            resController = xmlSignerService.reloadConfig();
            
        } catch (Exception ex) {
        	resController.setDescription("Error : " + ex.getMessage());
            resController.setStatus(FAILED_STATUS);
            //resController.setDigest(undefined_error_message + ": " + ex.getMessage());
            //resController.setNamespace(undefined_error_code);
            ex.printStackTrace();
            logger.info("[pdfSigner]: DigestDoc ResultCode: " + resController.getStatus());
            logger.debug("*******************End XmlSigner Reload session()********************");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(resController);
        }

        logger.info("[xmlSigner]: reload ResultCode: " + resController.getStatus());
        return ResponseEntity.status(HttpStatus.OK).body(resController);
    }

}
