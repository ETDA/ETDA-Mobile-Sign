package th.teda.xmlsigner.services;

import th.teda.xmlsigner.GetProperties;
import th.teda.xmlsigner.model.AttachSignatureRequest;
import th.teda.xmlsigner.model.AttachSignatureResponse;
import th.teda.xmlsigner.model.ComposeSignatureRequest;
import th.teda.xmlsigner.model.ComposeSignatureResponse;
import th.teda.xmlsigner.model.CreateSignedInfoRequest;
import th.teda.xmlsigner.model.CreateSignedInfoResponse;
import th.teda.xmlsigner.model.DigestDocRequest;
import th.teda.xmlsigner.model.DigestDocResponse;
import th.teda.xmlsigner.model.ReloadResponse;
import th.teda.xmlsigner.results.Results;

import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.HttpRetryException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.UnknownServiceException;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import th.teda.xmlsigner.configurations.Configurations;
import th.teda.xmlsigner.configurations.Constants;
import th.teda.xmlsigner.utils.GetCrlList;
import th.teda.xmlsigner.utils.GetOcspResp;
import th.teda.xmlsigner.utils.X509CertficateHelper;
//import th.teda.xades.XmlSigner;

import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;

import javax.xml.crypto.dsig.*;

//import th.teda.xmlsigner.results.Results.*;


@Service
public class XmlSignerServiceImpl implements XmlSignerService {
	
	private static Properties conProp;

	private byte[] signature = null;
	private X509Certificate cert = null;
	private DocumentBuilderFactory factory = null;
	private DocumentBuilder builder = null;
	private String digestAlgorithm = null;
	private String signatureAlgorithm = null;
	private String signatureId = null;
	private JSONObject jsonResult = null;
	private HashMap<String, Object> jsonMap = null;

	static {
		Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
	}

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public Boolean verifyDigestDocInput(DigestDocRequest request) {

        //logger.debug("[Verify Input]: Controller requests: transid: " + transid + ", transSubid: " + transSubid + ", fileid: " + fileid + ", fileType: " + fileType);
        boolean isInputFileHasText = StringUtils.hasText(request.getInputFile());
        boolean isDigestMethodHasText = StringUtils.hasText(request.getDigestMethod());
        
        return isInputFileHasText && isDigestMethodHasText;
    }

    @Override
    public Boolean verifyCreateSignedInfoInput(CreateSignedInfoRequest request) {

        //logger.debug("[Verify Input]: Controller requests: transid: " + transid + ", transSubid: " + transSubid + ", fileid: " + fileid + ", fileType: " + fileType);
        boolean isSignerCertHasText = StringUtils.hasText(request.getSignerCert());
        boolean isIssuerCertHasText = StringUtils.hasText(request.getIssuerCert());
        boolean isNamespaceHasText = StringUtils.hasText(request.getNamespace());
        boolean isDigestHasText = StringUtils.hasText(request.getDigest());
        boolean isDigestMethodHasText = StringUtils.hasText(request.getDigestMethod());
        boolean isSignatureMethodHasText = StringUtils.hasText(request.getSignatureMethod());
        
        return isSignerCertHasText && isIssuerCertHasText && isNamespaceHasText && isDigestHasText && isDigestMethodHasText && isSignatureMethodHasText;
    }

    @Override
    public Boolean verifyComposeSignatureInput(ComposeSignatureRequest request) {

        //logger.debug("[Verify Input]: Controller requests: transid: " + transid + ", transSubid: " + transSubid + ", fileid: " + fileid + ", fileType: " + fileType);
        boolean isSignatureIdHasText = StringUtils.hasText(request.getSignatureId());
        boolean isSignatureValueHasText = StringUtils.hasText(request.getSignatureValue());
        boolean isSignedInfoHasText = StringUtils.hasText(request.getSignedInfo());
        boolean isXadesSignedPropertiesHasText = StringUtils.hasText(request.getXadesSignedProperties());
        boolean isSignerCertHasText = StringUtils.hasText(request.getSignerCert());
        
        return isSignatureIdHasText && isSignatureValueHasText && isSignedInfoHasText && isXadesSignedPropertiesHasText && isSignerCertHasText;
    }

    @Override
    public Boolean verifyAttachSignatureInput(AttachSignatureRequest request) {

        //logger.debug("[Verify Input]: Controller requests: transid: " + transid + ", transSubid: " + transSubid + ", fileid: " + fileid + ", fileType: " + fileType);
        boolean isInputFileHasText = StringUtils.hasText(request.getInputFile());
        boolean isSignatureHasText = StringUtils.hasText(request.getSignature());
        
        return isInputFileHasText && isSignatureHasText;
    }

    @Override
    public DigestDocResponse digestDoc(DigestDocRequest request) throws Exception {

        String inputFile = null;
        String digestMethod = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        DigestDocResponse response = null;
        
        try {

//            Properties appProp = GetProperties.getPropertyFromPath(Results.appConfig);
//            String configPath = appProp.getProperty("configPath");
//
//            Properties conProp = GetProperties.getPropertyFromPath(configPath);
            inputFile = request.getInputFile();
            digestMethod = request.getDigestMethod();
            jsonResult = digestDocument(inputFile, digestMethod);
            jsonObj = new JSONObject(jsonResult);
            response = new DigestDocResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_DIGEST)) {
                response.setDigest(jsonObj.getString(Constants.LABEL_DIGEST));
            }
            if (jsonObj.has(Constants.LABEL_NAMESPACE)) {
                response.setNamespace(jsonObj.getString(Constants.LABEL_NAMESPACE));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: XMLSigner digestDoc Unknown ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new DigestDocResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

    @Override
    public CreateSignedInfoResponse createSignedInfo(CreateSignedInfoRequest request) throws Exception {

        String signerCert = null;
        String issuerCert = null;
        String namespace = null;
        String digest = null;
        String digestMethod = null;
        String signatureMethod = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        CreateSignedInfoResponse response = null;
        
        try {
            signerCert = request.getSignerCert();
            issuerCert = request.getIssuerCert();
            namespace = request.getNamespace();
            digest = request.getDigest();
            digestMethod = request.getDigestMethod();
            signatureMethod = request.getSignatureMethod();
            jsonResult = createSignedInfo(signerCert, issuerCert, namespace, digest, digestMethod, signatureMethod);
            jsonObj = new JSONObject(jsonResult);
            response = new CreateSignedInfoResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_SIGNATURE_ID)) {
                response.setSignatureId(jsonObj.getString(Constants.LABEL_SIGNATURE_ID));
            }
            if (jsonObj.has(Constants.LABEL_SIGNEDINFO)) {
                response.setSignedInfo(jsonObj.getString(Constants.LABEL_SIGNEDINFO));
            }
            if (jsonObj.has(Constants.LABEL_XADESSIGNEDPROPERTIES)) {
                response.setXadesSignedProperties(jsonObj.getString(Constants.LABEL_XADESSIGNEDPROPERTIES));
            }
            if (jsonObj.has(Constants.LABEL_SIGNEDINFO_DIGEST)) {
                response.setSignedInfoDigest(jsonObj.getString(Constants.LABEL_SIGNEDINFO_DIGEST));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: XMLSigner CreateSignedInfo ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new CreateSignedInfoResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

    @Override
    public ComposeSignatureResponse composeSignature(ComposeSignatureRequest request) throws Exception {

        String signatureId = null;
        String signatureValue = null;
        String signedInfo = null;
        String xadesSignedProperties = null;
        String signerCert = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        ComposeSignatureResponse response = null;
        
        try {
            signatureId = request.getSignatureId();
            signatureValue = request.getSignatureValue();
            signedInfo = request.getSignedInfo();
            xadesSignedProperties = request.getXadesSignedProperties();
            signerCert = request.getSignerCert();
            jsonResult = composeSignature(signatureId, signatureValue, signedInfo, xadesSignedProperties, signerCert);
            jsonObj = new JSONObject(jsonResult);
            response = new ComposeSignatureResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_SIGNATURE)) {
                response.setSignature(jsonObj.getString(Constants.LABEL_SIGNATURE));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: XMLSigner ComposeSignature ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new ComposeSignatureResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

    @Override
    public AttachSignatureResponse attachSignature(AttachSignatureRequest request) throws Exception {

        String inputFile = null;
        String signature = null;
        String jsonResult = null;
        JSONObject jsonObj = null;
        AttachSignatureResponse response = null;
        
        try {
            inputFile = request.getInputFile();
            signature = request.getSignature();
            jsonResult = attachSignature(inputFile, signature);
            jsonObj = new JSONObject(jsonResult);
            response = new AttachSignatureResponse();
            if (jsonObj.has(Constants.LABEL_DESCRIPTION)) {
            	response.setDescription(jsonObj.getString(Constants.LABEL_DESCRIPTION));
            }
            if (jsonObj.has(Constants.LABEL_STATUS)) {
                response.setStatus(jsonObj.getString(Constants.LABEL_STATUS));
            }
            if (jsonObj.has(Constants.LABEL_OUTPUT_FILE)) {
                response.setOutputFile(jsonObj.getString(Constants.LABEL_OUTPUT_FILE));
            }

        } catch (Exception ex) {
            logger.error("[" + "]: XMLSigner AttachSignature ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new AttachSignatureResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

    @Override
    public ReloadResponse reloadConfig() throws Exception {
        
        ReloadResponse response = null;

        try {
        	conProp = GetProperties.getPropertyFromPath(Configurations.configPath);
    		digestAlgorithm = conProp.getProperty(Constants.DEFAULT_DIGEST_ALGO);
    		signatureAlgorithm = conProp.getProperty(Constants.DEFAULT_SIGNATURE_ALGO);
    		setSignatureId(generateSignatureId());
            response = new ReloadResponse();           
            response.setStatus(Results.SUCCESS_STATUS);
        } catch (Exception ex) {
            logger.error("[" + "]: XMLSigner Reload ERROR: " + ex.getMessage());
            ex.printStackTrace();
            response = new ReloadResponse();
            response.setDescription("Error : " + ex.getMessage());
            response.setStatus(Results.FAILED_STATUS);
        }

        logger.debug("*******************End session()********************");
        return response;

    }

	public XmlSignerServiceImpl() throws Exception {
		try {
			init();
		} catch (Exception e) {
			throw e;
		}
	}

	public X509Certificate getCertificate() {
		return cert;
	}

	public byte[] getSignature() {
		return signature;
	}

	private void init() throws Exception {

		factory = null;
		builder = null;
		org.apache.xml.security.Init.init();

		factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);

		try {
			builder = factory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw e;
		}
		
        conProp = GetProperties.getPropertyFromPath(Configurations.configPath);
		digestAlgorithm = conProp.getProperty(Constants.DEFAULT_DIGEST_ALGO);
		signatureAlgorithm = conProp.getProperty(Constants.DEFAULT_SIGNATURE_ALGO);
		setSignatureId(generateSignatureId());

	}

	public HashMap<String, String> getNamespaceAttr(Document doc) throws Exception {

		// Here comes the root node
		Element rootElem = doc.getDocumentElement();
		Node rootNode = rootElem.cloneNode(true);
		NamedNodeMap rootAttr = rootNode.getAttributes();
		HashMap<String, String> rootNs = new HashMap<String, String>();

		for (int i = 0; i < rootAttr.getLength(); i++) {
			if (rootAttr.item(i).getNodeName().startsWith("xmlns:") || rootAttr.item(i).getNodeName().equals("xmlns")) {
				rootNs.put(rootAttr.item(i).getNodeName(), rootAttr.item(i).getNodeValue());
			}
		}

		return rootNs;
	}

//	public String mobileSignedData(String inputStr, byte[] inputByte, String P12Path, String password)
//			throws Exception {
//
//		return mobileSignedData(inputStr, inputByte, P12Path, password, prop.getProperty(DEFAULT_SIGNATURE_ALGO));
//	}
//
//	public String mobileSignedData(String inputStr, byte[] inputByte, String P12Path, String password,
//			String signAlgorithm) throws Exception {
//
//		PrivateKey privateKey = null;
//		byte[] data = null;
//
//		if (inputStr != null) {
//			data = inputStr.getBytes();
//		} else {
//			data = inputByte;
//		}
//
//		KeyStore ks = KeyStore.getInstance("PKCS12");
//		ks.load(new FileInputStream(P12Path), password.toCharArray());
//
//		Enumeration<String> aliases = ks.aliases();
//		while (aliases.hasMoreElements()) {
//			String alias = (String) aliases.nextElement();
//			Key key = ks.getKey(alias, password.toCharArray());
//			if (key instanceof PrivateKey) {
//				privateKey = (PrivateKey) key;
//			}
//		}
//
//		Signature sig = Signature.getInstance(signAlgorithm);
//		sig.initSign(privateKey);
//		sig.update(data);
//		signature = sig.sign();
//
//		String result = Base64.toBase64String(signature);
//		return result;
//	}

	public Node composeSignature(Node signedInfo, String signatureValue, X509Certificate certificate,
			Node xadesSignedPropNode) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		return composeSignature(doc, signedInfo, signatureValue, certificate, xadesSignedPropNode);
	}

	private Node composeSignature(Document doc, Node signedInfo, String signatureValue, X509Certificate certificate,
			Node xadesSignedPropNode) throws Exception {

		Element signatureElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Signature");

		signatureElem.setAttribute("Id", String.format("%s", signatureId));
		Node signedInfoNode = doc.importNode(signedInfo, true);
		signatureElem.appendChild(signedInfoNode);

		Element sigValueElem = doc.createElementNS(XMLSignature.XMLNS, "ds:SignatureValue");

		sigValueElem.setAttribute("Id", String.format("%s-sigvalue", signatureId));
		sigValueElem.appendChild(doc.createTextNode(signatureValue));

		signatureElem.appendChild(sigValueElem);
		Node keyInfoNode = doc.importNode(createKeyInfoElement(doc, certificate), true);
		signatureElem.appendChild(keyInfoNode);

		Node xadesObjectNode = doc.importNode(createXadesObjectElement(certificate, xadesSignedPropNode), true);
		signatureElem.appendChild(xadesObjectNode);

		return signatureElem;
	}

	public String composeSignature(String id, String signatureValue, String signedInfoString,
			String xadesSignedPropString, String signerCertString) {

		X509Certificate signerCert = null;
		String jsonString = null;
		Node signedInfoNode = null;
		Node xadesSignedPropNode = null;
		Node signatureNode = null;
		byte[] signatureByte = null;
		String signatureString = null;

		try {

			setSignatureId(id);
			signedInfoNode = createNode(Base64.decode(signedInfoString.getBytes()));
			xadesSignedPropNode = createNode(Base64.decode(xadesSignedPropString.getBytes()));
			signerCert = X509CertficateHelper.convertBase64toX509(signerCertString);

			signatureNode = composeSignature(signedInfoNode, signatureValue, signerCert, xadesSignedPropNode);
			//signatureByte = Serializer.serialize(signatureNode);
			signatureByte = canonicalizeNode(signatureNode);
			signatureString = Base64.toBase64String(signatureByte);

			jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_SIGNATURE, signatureString);

			jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
	        logger.debug("[xmlSigner]: ComposeSignature Result: " + jsonString);
			//System.out.println(jsonString);

		} catch (Exception e) {
			jsonString = writeError(e);
		}

		return jsonString;
	}

	public void createSignedInfoElementFile(String inputPath, String outputPath, String xadesDigestValuePath,
			String signatureId) throws Exception {

		Document xmlDoc = null;
		Document signedInfoDoc = null;

		// Build Document
		xmlDoc = createDocument(inputPath);
		signedInfoDoc = createDocument();

		xmlDoc.getDocumentElement().normalize();

		DOMSource source = null;
		TransformerFactory transformerFactory = null;
		Transformer transf = null;

		byte canonXmlDigestByte[] = null;
		canonXmlDigestByte = digestDocument(xmlDoc);

		HashMap<String, String> rootNsMap = getNamespaceAttr(xmlDoc);

		byte[] xadesDigestValue = null;
		try {
			File xadesDigestValueFile = new File(xadesDigestValuePath);
			FileInputStream fis = new FileInputStream(xadesDigestValueFile);
			xadesDigestValue = new byte[(int) xadesDigestValueFile.length()];
			fis.read(xadesDigestValue);
			fis.close();
		} catch (FileNotFoundException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		}

		Node signedInfo = createSignedInfoElement(canonXmlDigestByte, rootNsMap, xadesDigestValue, signatureId);
		Node signedInfoNode = signedInfoDoc.importNode(signedInfo, true);
		signedInfoDoc.appendChild(signedInfoNode);

		source = new DOMSource(signedInfoDoc);
		transformerFactory = TransformerFactory.newInstance();

		try {
			transf = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw e;
		}

		StreamResult outPutFile = new StreamResult(new File(outputPath));

		try {
			transf.transform(source, outPutFile);
		} catch (TransformerException e) {
			throw e;
		}
	}

	public String createSignedInfo(String signerCertString, String issuerCertString, String namespaces,
			String documentDigestValue, String digestMethod, String signatureMethod) {

		X509Certificate signerCert = null;
		X509Certificate issuerCert = null;
		HashMap<String, String> nsMap = null;
		String[] nsStringArray = null;
		String signatureId = null;
		String digestAlgo = null;
		String signatureAlgo = null;

		Document doc = null;
		String jsonString = null;
		String warnMsg = null;

		try {
			signerCert = X509CertficateHelper.convertBase64toX509(signerCertString);
			issuerCert = X509CertficateHelper.convertBase64toX509(issuerCertString);
		} catch (Exception e) {
			jsonString = writeError(e);
			return jsonString;
		}

		try {
			setCertificate(signerCert);
		} catch (Exception e) {
			jsonString = writeError(conProp.getProperty(Constants.CODE_CERT_FORMAT_INVALID));
			return jsonString;
		}

		try {
			cert.checkValidity();
		} catch (Exception e) {
			jsonString = writeError(e);
			return jsonString;
		}

		try {
			verifyOcspCrl(issuerCert);
		} catch (HttpRetryException | SocketTimeoutException | ProtocolException | SocketException | UnknownHostException | UnknownServiceException e) {
			warnMsg = conProp.getProperty(Constants.CODE_OCSP_CRL_CONNECTION_ERROR);
		}
		catch (MalformedURLException | URISyntaxException e) {
			jsonString = writeError(e);
			return jsonString;
		}
		catch (Exception e) {
			if (e instanceof CertificateException && 
					(e.getMessage().equals(conProp.getProperty(Constants.CODE_CERT_REVOKED)) || 
					e.getMessage().equals(conProp.getProperty(Constants.CODE_CDP_NOT_FOUND)))) {
				jsonString = writeError(e);
				return jsonString;				
			}
			
			else {
				warnMsg = conProp.getProperty(Constants.CODE_OCSP_CRL_CONNECTION_ERROR);
			}
		}

		try {
			nsStringArray = namespaces.split(";");

			digestAlgo = getMessageDigestAlgorithm(digestMethod);
			setDigestAlgorithm(digestAlgo);
			signatureAlgo = getSignatureAlgorithm(signatureMethod);
			setSignatureAlgorithm(signatureAlgo);
			signatureId = generateSignatureId();
			setSignatureId(signatureId);

			// Build Document
			doc = createDocument();
			nsMap = new HashMap<String, String>();

			for (int i = 0; i < nsStringArray.length; i++) {
				if (!nsStringArray[i].equals("")) {
					String[] attributeString = nsStringArray[i].split("=", 2);
					Attr nsAttr = doc.createAttribute(attributeString[0]);
					nsAttr.setValue(attributeString[1]);
					nsMap.put(attributeString[0], attributeString[1]);
				}
			}

			Node xadesSignedPropNode = null;
			byte[] xadesSignedPropDigestValue = null;
			xadesSignedPropNode = createXadesSignedPropElement(doc, signerCert, nsMap);
			xadesSignedPropDigestValue = digestNode(xadesSignedPropNode);

			// Build Document
			doc = createDocument();
			Node signedInfoNode = null;

			signedInfoNode = createSignedInfoElement(doc, Base64.decode(documentDigestValue.getBytes()), nsMap,
					xadesSignedPropDigestValue);

			byte[] xadesSignedPropCanonByte = null;
			byte[] signedInfoCanonByte = null;
			byte[] signedInfoDigestByte = null;

			xadesSignedPropCanonByte = canonicalizeNode(xadesSignedPropNode);
			signedInfoCanonByte = canonicalizeNode(signedInfoNode);

			signedInfoDigestByte = digestNode(signedInfoNode);

			jsonMap = new HashMap<String, Object>();

			if (warnMsg != null) {
				jsonMap.put(Constants.LABEL_STATUS, Results.WARNING_STATUS);
				jsonMap.put(Constants.LABEL_DESCRIPTION, warnMsg);	
			} else {
				jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			}			
			jsonMap.put(Constants.LABEL_SIGNATURE_ID, signatureId);
			jsonMap.put(Constants.LABEL_SIGNEDINFO, Base64.toBase64String(signedInfoCanonByte));
			jsonMap.put(Constants.LABEL_SIGNEDINFO_DIGEST, Base64.toBase64String(signedInfoDigestByte));
			jsonMap.put(Constants.LABEL_XADESSIGNEDPROPERTIES, Base64.toBase64String(xadesSignedPropCanonByte));

			jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
	        logger.debug("[xmlSigner]: CreateSignedInfo Result: " + jsonString);
	        //System.out.println(jsonString);

		} catch (Exception e) {
			jsonString = writeError(e);
		}

		return jsonString;
	}

	public Node createSignedInfoElement(byte[] documentDigestValue, HashMap<String, String> nsMap,
			byte[] xadesSignedPropDigestValue, String signatureId) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		Node signedInfoNode = null;
		signedInfoNode = createSignedInfoElement(doc, documentDigestValue, nsMap, xadesSignedPropDigestValue);

		return signedInfoNode;
	}

	private Node createSignedInfoElement(Document doc, byte[] documentDigestValue, HashMap<String, String> nsMap,
			byte[] xadesSignedPropDigestValue) throws Exception {

		Element signedInfoElem = doc.createElementNS(XMLSignature.XMLNS, "ds:SignedInfo");

		for (Map.Entry<String, String> entry : nsMap.entrySet()) {
			signedInfoElem.setAttribute(entry.getKey(), entry.getValue());
		}

		Element canonMethElem = doc.createElementNS(XMLSignature.XMLNS, "ds:CanonicalizationMethod");
		canonMethElem.setAttribute("Algorithm", CanonicalizationMethod.INCLUSIVE);
		signedInfoElem.appendChild(canonMethElem);

		String signAlgoURI = null;
		signAlgoURI = getSignatureAlgorithmUri(signatureAlgorithm);

		Element signMethElem = doc.createElementNS(XMLSignature.XMLNS, "ds:SignatureMethod");
		signMethElem.setAttribute("Algorithm", signAlgoURI);
		signedInfoElem.appendChild(signMethElem);

		Node referenceNode = doc.importNode(createReferenceElement(documentDigestValue, digestAlgorithm, signatureId),
				true);
		signedInfoElem.appendChild(referenceNode);

		Node xadesSignedPropRefElem = null;
		xadesSignedPropRefElem = this.createSignedPropReferenceElement(doc, xadesSignedPropDigestValue);

		signedInfoElem.appendChild(xadesSignedPropRefElem);

		return signedInfoElem;
	}

	public Node createReferenceElement(byte[] documentDigestValue, String digestAlgorithm, String signatureId)
			throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		Node referenceNode = null;

		referenceNode = createReferenceElement(doc, documentDigestValue, digestAlgorithm, signatureId);

		return referenceNode;
	}

	private Node createReferenceElement(Document doc, byte[] documentDigestValue, String digestAlgorithm,
			String signatureId) throws Exception {

		Element referenceElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Reference");
		referenceElem.setAttribute("Id", String.format("%s-ref0", signatureId));
		referenceElem.setAttribute("URI", "");

		Element transformsElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Transforms");

		Element transformElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Transform");
		transformElem.setAttribute("Algorithm", Transform.ENVELOPED);

		transformsElem.appendChild(transformElem);
		referenceElem.appendChild(transformsElem);

		String digestAlgoUri = null;

		digestAlgoUri = getMessageDigestAlgorithmUri(digestAlgorithm);

		Element digestMethElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestMethod");
		digestMethElem.setAttribute("Algorithm", digestAlgoUri);
		referenceElem.appendChild(digestMethElem);

		Element digestValueElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestValue");

		digestValueElem.appendChild(doc.createTextNode(Base64.toBase64String(documentDigestValue)));

		referenceElem.appendChild(digestValueElem);

		return referenceElem;
	}

	public Node createSignedPropReferenceElement(byte[] xadesDigestValue) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		Node signedPropRefNode = null;

		signedPropRefNode = createSignedPropReferenceElement(doc, xadesDigestValue);

		return signedPropRefNode;
	}

	private Node createSignedPropReferenceElement(Document doc, byte[] xadesDigestValue) throws Exception {

		Element referenceElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Reference");
		referenceElem.setAttribute("Type", Constants.SIGNED_PROPS_TYPE_URI);
		referenceElem.setAttribute("URI", String.format("#%s-signedprops", signatureId));

		String digestAlgoUri = null;
		digestAlgoUri = getMessageDigestAlgorithmUri(digestAlgorithm);

		Element digestMethElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestMethod");
		digestMethElem.setAttribute("Algorithm", digestAlgoUri);
		referenceElem.appendChild(digestMethElem);

		Element digestValueElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestValue");
		digestValueElem.appendChild(doc.createTextNode(Base64.toBase64String(xadesDigestValue)));

		referenceElem.appendChild(digestValueElem);

		return referenceElem;
	}

	public Node createXadesObjectElement(X509Certificate certificate, Node xadesSignedProp) {

		Document doc = null;

		// Build Document
		doc = createDocument();

		return createXadesObjectElement(doc, certificate, xadesSignedProp);
	}

	private Node createXadesObjectElement(Document doc, X509Certificate certificate, Node xadesSignedProp) {

		Element objectElem = doc.createElementNS(XMLSignature.XMLNS, "ds:Object");

		Element xadesQualifyElem = doc.createElementNS(Constants.XADES_NS, "xades:QualifyingProperties");
		xadesQualifyElem.setAttribute("xmlns:xades141", Constants.XADES141_NS);
		xadesQualifyElem.setAttribute("Target", String.format("#%s", signatureId));
		objectElem.appendChild(xadesQualifyElem);

		Node xadesSignedPropNode = doc.importNode(xadesSignedProp, true);
		xadesQualifyElem.appendChild(xadesSignedPropNode);

		return objectElem;
	}

	public Node createXadesSignedPropElement(X509Certificate certificate, HashMap<String, String> rootNs)
			throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		return createXadesSignedPropElement(doc, certificate, rootNs);
	}

	private Node createXadesSignedPropElement(Document doc, X509Certificate certificate, HashMap<String, String> rootNs)
			throws Exception {

		Element xadesSignedPropertyElem = doc.createElementNS(Constants.XADES_NS, "xades:SignedProperties");
		xadesSignedPropertyElem.setAttribute("Id", String.format("%s-signedprops", signatureId));
		xadesSignedPropertyElem.setAttribute("xmlns:ds", XMLSignature.XMLNS);
		xadesSignedPropertyElem.setAttribute("xmlns:xades141", Constants.XADES141_NS);

		for (Map.Entry<String, String> entry : rootNs.entrySet()) {
			xadesSignedPropertyElem.setAttribute(entry.getKey(), entry.getValue());
		}

		Element xadesSignedSignaturePropertyElem = doc.createElementNS(Constants.XADES_NS,
				"xades:SignedSignatureProperties");
		xadesSignedPropertyElem.appendChild(xadesSignedSignaturePropertyElem);

		Element xadesSigningTimeElem = doc.createElementNS(Constants.XADES_NS, "xades:SigningTime");
		GregorianCalendar signingTime = new GregorianCalendar();
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
		String dateString = dateFormat.format(signingTime.getTime());
		xadesSigningTimeElem.appendChild(doc.createTextNode(dateString));
		xadesSignedSignaturePropertyElem.appendChild(xadesSigningTimeElem);

		Element xadesSigningCertificateElem = doc.createElementNS(Constants.XADES_NS, "xades:SigningCertificate");
		xadesSignedSignaturePropertyElem.appendChild(xadesSigningCertificateElem);

		Element xadesCertElem = doc.createElementNS(Constants.XADES_NS, "xades:Cert");
		xadesSigningCertificateElem.appendChild(xadesCertElem);

		Element xadesCertDigestElem = doc.createElementNS(Constants.XADES_NS, "xades:CertDigest");
		xadesCertElem.appendChild(xadesCertDigestElem);

		String digestAlgoUri = getMessageDigestAlgorithmUri(digestAlgorithm);
		Element digestMethElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestMethod");
		digestMethElem.setAttribute("Algorithm", digestAlgoUri);
		xadesCertDigestElem.appendChild(digestMethElem);

		Element digestValueElem = doc.createElementNS(XMLSignature.XMLNS, "ds:DigestValue");
		MessageDigest certDigest = null;

		try {
			certDigest = MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw e;
		}

		try {
			digestValueElem.appendChild(
					doc.createTextNode(Base64.toBase64String(certDigest.digest(certificate.getEncoded()))));
		} catch (CertificateEncodingException e) {
			throw e;
		} catch (DOMException e) {
			throw e;
		}

		xadesCertDigestElem.appendChild(digestValueElem);

		Element xadesIssuerSerialElem = doc.createElementNS(Constants.XADES_NS, "xades:IssuerSerial");
		xadesCertElem.appendChild(xadesIssuerSerialElem);

		Element x509IssuerNameElem = doc.createElementNS(XMLSignature.XMLNS, "ds:X509IssuerName");
		x509IssuerNameElem.appendChild(doc.createTextNode(certificate.getIssuerDN().toString()));
		xadesIssuerSerialElem.appendChild(x509IssuerNameElem);

		Element x509SerialNumberElem = doc.createElementNS(XMLSignature.XMLNS, "ds:X509SerialNumber");
		x509SerialNumberElem.appendChild(doc.createTextNode(certificate.getSerialNumber().toString()));
		xadesIssuerSerialElem.appendChild(x509SerialNumberElem);

		return xadesSignedPropertyElem;
	}

//	public void createXadesSignedPropFile(String outputPath, String outputDigestPath, String p12Path,
//			String p12Password, HashMap<String, String> rootNs) throws Exception {
//
//		Node xadesSignedPropElem = null;
//
//		this.setCertificate(p12Path, p12Password);
//
//		Document xadesSignedPropDoc = builder.newDocument();
//		xadesSignedPropDoc.setXmlStandalone(true);
//		xadesSignedPropElem = this.createXadesSignedPropElement(cert, rootNs);
//		Node xadesSignedPropNode = xadesSignedPropDoc.importNode(xadesSignedPropElem, true);
//		xadesSignedPropDoc.appendChild(xadesSignedPropNode);
//
//		ByteArrayOutputStream bos = new ByteArrayOutputStream();
//		DOMSource source = new DOMSource(xadesSignedPropDoc);
//		StreamResult result = new StreamResult(bos);
//		TransformerFactory transformerFactory = TransformerFactory.newInstance();
//		Transformer transf = null;
//
//		try {
//			transf = transformerFactory.newTransformer();
//		} catch (TransformerConfigurationException e) {
//			throw e;
//		}
//
//		try {
//			transf.transform(source, result);
//		} catch (TransformerException e) {
//			throw e;
//		}
//
//		byte[] xadesSignedPropBytes = null;
//		byte canonXadesSignedPropDigestBytes[] = null;
//		MessageDigest signedPropDigest = null;
//
//		xadesSignedPropBytes = bos.toByteArray();
//
//		try {
//			signedPropDigest = MessageDigest.getInstance(digestAlgorithm);
//		} catch (NoSuchAlgorithmException e) {
//			throw e;
//		}
//
//		Canonicalizer canon = null;
//		try {
//			canon = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
//		} catch (InvalidCanonicalizerException e) {
//			throw e;
//		}
//
//		try {
//			canonXadesSignedPropDigestBytes = signedPropDigest.digest(canon.canonicalize(xadesSignedPropBytes));
//		} catch (CanonicalizationException e) {
//			throw e;
//		} catch (ParserConfigurationException e) {
//			throw e;
//		} catch (IOException e) {
//			throw e;
//		} catch (SAXException e) {
//			throw e;
//		}
//
//		StreamResult outputFile = null;
//		outputFile = new StreamResult(new File(outputPath));
//
//		try {
//			transf.transform(source, outputFile);
//		} catch (TransformerException e) {
//			throw e;
//		}
//
//		try {
//			FileOutputStream outputHashFile = new FileOutputStream(outputDigestPath);
//			outputHashFile.write(canonXadesSignedPropDigestBytes);
//			outputHashFile.close();
//		} catch (IOException e) {
//			throw e;
//		}
//
//	}

	public Node createKeyInfoElement(X509Certificate certificate) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		return createKeyInfoElement(doc, certificate);
	}

	private Node createKeyInfoElement(Document doc, X509Certificate certificate) throws Exception {

		Element keyInfoElem = doc.createElementNS(XMLSignature.XMLNS, "ds:KeyInfo");
		Element x509DataElem = doc.createElementNS(XMLSignature.XMLNS, "ds:X509Data");
		Element x509SubjectNameElem = doc.createElementNS(XMLSignature.XMLNS, "ds:X509SubjectName");

		x509SubjectNameElem.appendChild(doc.createTextNode(certificate.getSubjectX500Principal().getName()));

		Element x509CertificateElem = doc.createElementNS(XMLSignature.XMLNS, "ds:X509Certificate");
		try {
			x509CertificateElem.appendChild(doc.createTextNode(Base64.toBase64String(certificate.getEncoded())));
		} catch (CertificateEncodingException | DOMException e) {
			throw e;
		}

		x509DataElem.appendChild(x509SubjectNameElem);
		x509DataElem.appendChild(x509CertificateElem);
		keyInfoElem.appendChild(x509DataElem);

		return keyInfoElem;
	}

    public byte[] digestDocument(String inputFile) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument(inputFile);

		doc.getDocumentElement().normalize();

		return digestDocument(doc);
	}

	private String digestDocument(String inputFile, String digestMethod) {

		String digestAlgo = null;
		byte canonXmlDigestByte[] = null;
		String canonXmlDigestString = null;
		Document doc = null;
		String nsArray = null;
		String jsonString = null;

		try {
			digestAlgo = getMessageDigestAlgorithm(digestMethod);
			setDigestAlgorithm(digestAlgo);

			canonXmlDigestByte = digestDocument(inputFile);

			canonXmlDigestString = Base64.toBase64String(canonXmlDigestByte);

			doc = createDocument(inputFile);
			HashMap<String, String> nsMap = getNamespaceAttr(doc);

			nsArray = new String();
			int mapItr = 0;
			for (Map.Entry<String, String> entry : nsMap.entrySet()) {
				nsArray += entry.getKey() + "=" + entry.getValue();
				if (mapItr < nsMap.size() - 1) {
					nsArray += ";";
					mapItr++;
				}
			}

			jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_DIGEST, canonXmlDigestString);
			jsonMap.put(Constants.LABEL_NAMESPACE, nsArray);

			jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
	        logger.debug("[xmlSigner]: DigestDoc Result: " + jsonString);
	        //System.out.println(jsonString);
		} catch (Exception e) {
			jsonString = writeError(e);
		}

		return jsonString;
	}

	public byte[] digestDocument(Document doc) throws Exception {

		MessageDigest xmlDigest = null;

		try {
			xmlDigest = MessageDigest.getInstance(digestAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			throw e;
		}

		byte canonXmlDigestByte[] = null;
		canonXmlDigestByte = xmlDigest.digest(canonicalizeDocument(doc));

		return canonXmlDigestByte;
	}

	public byte[] digestNode(Node node) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		Node digestNode = doc.importNode(node, true);
		doc.appendChild(digestNode);

		doc.getDocumentElement().normalize();

		return digestDocument(doc);

	}

	private Document createDocument(String inputFile) throws Exception {
		Document doc = null;

		// Build Document
		try {
			byte[] decodedBytes = java.util.Base64.getDecoder().decode(inputFile.getBytes(StandardCharsets.UTF_8));
			InputStream is = new ByteArrayInputStream(decodedBytes);
			doc = builder.parse(is);
			doc.setXmlStandalone(true);
		} catch (SAXException | IOException e) {
			throw e;
		}

		return doc;
	}

	private Document createDocument() {
		Document doc = null;

		// Build Document
		doc = builder.newDocument();
		doc.setXmlStandalone(true);
		return doc;
	}

	private Node createNode(byte[] bytes) throws Exception {

		Document doc = null;
		Node node = null;
		// Build Document
		try {
			doc = builder.parse(new ByteArrayInputStream(bytes));
			doc.setXmlStandalone(true);
			node = doc.getDocumentElement();
		} catch (SAXException | IOException e) {
			throw e;
		}

		return node;
	}

	public void attachSignature(Document doc, Node node, String outputPath) throws Exception {

		DOMSource source = null;
		TransformerFactory transformerFactory = null;
		Transformer transf = null;

		doc.setXmlStandalone(true);

		Node importNode = doc.importNode(node, true);
		doc.getLastChild().appendChild(importNode);

		source = new DOMSource(doc);
		transformerFactory = TransformerFactory.newInstance();

		try {
			transf = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw e;
		}
		StreamResult outPutFile = new StreamResult(new File(outputPath));

		try {
			transf.transform(source, outPutFile);
		} catch (TransformerException e) {
			throw e;
		}

	}

	public String attachSignature(String inputFile, String signatureString) {

		String jsonString = null;

		Document doc = null;
		DOMSource source = null;
		TransformerFactory transformerFactory = null;
		Transformer transf = null;

		try {
			doc = createDocument(inputFile);
			doc.setXmlStandalone(true);

			Node signatureNode;
			signatureNode = createNode(Base64.decode(signatureString.getBytes()));

			Node importNode = doc.importNode(signatureNode, true);
			doc.getLastChild().appendChild(importNode);

			source = new DOMSource(doc);
			transformerFactory = TransformerFactory.newInstance();

			try {
				transf = transformerFactory.newTransformer();
			} catch (TransformerConfigurationException e) {
				throw e;
			}
			ByteArrayOutputStream os = new ByteArrayOutputStream(); 
			StreamResult outputStreamResult = new StreamResult(os);
			
			try {
				transf.transform(source, outputStreamResult);
			} catch (TransformerException e) {
				throw e;
			}

			String outputSignature = new String(java.util.Base64.getEncoder().encode(os.toByteArray()));
			jsonMap = new HashMap<String, Object>();
			jsonMap.put(Constants.LABEL_STATUS, Results.SUCCESS_STATUS);
			jsonMap.put(Constants.LABEL_OUTPUT_FILE, outputSignature);
			jsonResult = new JSONObject(jsonMap);
			jsonString = jsonResult.toString();
	        logger.debug("[xmlSigner]: AttachSignature Result: " + jsonString);
			//System.out.println(jsonString);

		} catch (Exception e) {
			jsonString = writeError(e);
		}
		return jsonString;
	}

	public byte[] canonicalizeDocument(Document doc) throws Exception {

		doc.getDocumentElement().normalize();

		ByteArrayOutputStream bos = null;
		DOMSource source = null;
		StreamResult result = null;
		TransformerFactory transformerFactory = null;
		Transformer transf = null;

		bos = new ByteArrayOutputStream();
		source = new DOMSource(doc);
		result = new StreamResult(bos);
		transformerFactory = TransformerFactory.newInstance();

		try {
			transf = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw e;
		}
		try {
			transf.transform(source, result);
		} catch (TransformerException e) {
			throw e;
		}

		byte[] xmlBytes = bos.toByteArray();
		Canonicalizer canon = null;
		try {
			canon = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
		} catch (InvalidCanonicalizerException e) {
			throw e;
		}
		byte canonXmlByte[] = null;
		try {
			canonXmlByte = canon.canonicalize(xmlBytes);
		} catch (CanonicalizationException e) {
			throw e;
		} catch (ParserConfigurationException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		} catch (SAXException e) {
			throw e;
		}

		return canonXmlByte;
	}

	public byte[] canonicalizeNode(Node node) throws Exception {

		Document doc = null;

		// Build Document
		doc = createDocument();

		Node canonNode = doc.importNode(node, true);
		doc.appendChild(canonNode);

		doc.getDocumentElement().normalize();

		ByteArrayOutputStream bos = null;
		DOMSource source = null;
		StreamResult result = null;
		TransformerFactory transformerFactory = null;
		Transformer transf = null;

		bos = new ByteArrayOutputStream();
		source = new DOMSource(doc);
		result = new StreamResult(bos);
		transformerFactory = TransformerFactory.newInstance();

		try {
			transf = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw e;
		}
		try {
			transf.transform(source, result);
		} catch (TransformerException e) {
			throw e;
		}

		byte[] xmlBytes = bos.toByteArray();
		Canonicalizer canon = null;
		try {
			canon = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
		} catch (InvalidCanonicalizerException e) {
			throw e;
		}
		byte canonXmlByte[] = null;
		try {
			canonXmlByte = canon.canonicalize(xmlBytes);
		} catch (CanonicalizationException e) {
			throw e;
		} catch (ParserConfigurationException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		} catch (SAXException e) {
			throw e;
		}

		return canonXmlByte;
	}

	public String writeError(String erMsg) {

		return writeError(new Exception(erMsg));
	}

	public String writeError(Exception e) {

		HashMap<String, Object> errorMap = null;
		JSONObject errorOut = null;
		String errorMessage = null;
		String errorString = null;

		e.printStackTrace();
		errorMap = new HashMap<String, Object>();
		errorMessage = Constants.LABEL_DESCRIPTION_ERROR + e.getMessage();

		errorMap.put(Constants.LABEL_STATUS, Results.FAILED_STATUS);
		errorMap.put(Constants.LABEL_DESCRIPTION, errorMessage);

		errorOut = new JSONObject(errorMap);
		errorString = errorOut.toString();
		//System.out.println(errorString);
		
		return errorString;
	}

	public String generateWarning(String warnMsg) {

		HashMap<String, Object> warnMap = null;
		JSONObject warnOut = null;
		String warnMessage = null;
		String warnString = null;

		warnMap = new HashMap<String, Object>();
		warnMessage = warnMsg;

		warnMap.put(Constants.LABEL_STATUS, Results.WARNING_STATUS);
		warnMap.put(Constants.LABEL_DESCRIPTION, warnMessage);

		warnOut = new JSONObject(warnMap);
		warnString = warnOut.toString();
		
		return warnString;
	}

//	public void setCertificate(String P12Path, String password) throws Exception {
//
//		KeyStore ks = KeyStore.getInstance("PKCS12");
//		ks.load(new FileInputStream(P12Path), password.toCharArray());
//
//		Enumeration<String> aliases = ks.aliases();
//		while (aliases.hasMoreElements()) {
//			String alias = (String) aliases.nextElement();
//			Key key = ks.getKey(alias, password.toCharArray());
//			if (key instanceof PrivateKey) {
//				cert = (X509Certificate) ks.getCertificate(alias);
//			}
//		}
//	}
//
	public void setCertificate(X509Certificate certificate) throws Exception {
		cert = certificate;
	}

	public void verifyOcspCrl(X509Certificate issuerCert) throws Exception {

		GetOcspResp ocspResp = new GetOcspResp();

		try {
			OCSPResp ocspResponse = ocspResp.getOcspResp(cert, issuerCert);
			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
			SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();

			if (responses != null && responses.length == 1) {
				SingleResp resp = responses[0];
				CertificateStatus status = resp.getCertStatus();
				if (CertificateStatus.GOOD == status) {
					return;
				} 
				else if (status instanceof RevokedStatus) {
					throw new CertificateException(conProp.getProperty(Constants.CODE_CERT_REVOKED));
				}
				else if (status instanceof UnknownStatus) {
					throw new CertificateException(conProp.getProperty(Constants.CODE_OCSP_CRL_CONNECTION_ERROR));					
				}
			}
		} catch (Exception e) {
			if (e.getMessage().equals(conProp.getProperty(Constants.CODE_CERT_REVOKED))) {
				throw e;
			}
			else 
			{
				List<CRL> crlList = new GetCrlList().readCRLsFromCert((X509Certificate) cert);
				if (crlList.isEmpty()) {
					throw new CertificateException(conProp.getProperty(Constants.CODE_CDP_NOT_FOUND));
				}
				X509CRL crl = (X509CRL) crlList.get(0);
				X509CRLEntry revoked = crl.getRevokedCertificate(cert);
				if (revoked != null) {
					throw new CertificateException(conProp.getProperty(Constants.CODE_CERT_REVOKED));
				}
			}
		}
	}

//	private String getDigestAlgorithm() {
//
//		return digestAlgorithm;
//	}

	private void setDigestAlgorithm(String name) {

		digestAlgorithm = name;
	}

//	private String getSignatureAlgorithm() {
//
//		return signatureAlgorithm;
//	}

	private void setSignatureAlgorithm(String id) {

		signatureAlgorithm = id;
	}

	public String getSignatureId() {

		return signatureId;
	}

	public void setSignatureId(String id) {

		signatureId = id;
	}

	public static String generateSignatureId() {

		String signatureId = null;
		signatureId = String.format("xmldsig-%s", UUID.randomUUID());
		return signatureId;
	}

	public static String getMessageDigestAlgorithmUri(String algorithmName) throws Exception {

		String digestAlgoUri = null;
		switch (algorithmName) {
		case "SHA-1":
			digestAlgoUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
			break;
		case "SHA-224":
			digestAlgoUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224;
			break;
		case "SHA-256":
			digestAlgoUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
			break;
		case "SHA-384":
			digestAlgoUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384;
			break;
		case "SHA-512":
			digestAlgoUri = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
			break;
		default:
			throw new NoSuchAlgorithmException(conProp.getProperty(Constants.CODE_DIGEST_ALGO_NOT_SUPPORTED));
		}
		return digestAlgoUri;
	}

	public static String getMessageDigestAlgorithm(String algorithmMethod) throws Exception {

		String digestAlgoName = null;
		switch (algorithmMethod) {
		case "1":
			digestAlgoName = MessageDigestAlgorithms.SHA_256;
			break;
		case "2":
			digestAlgoName = MessageDigestAlgorithms.SHA_384;
			break;
		case "3":
			digestAlgoName = MessageDigestAlgorithms.SHA_512;
			break;
		default:
			throw new NoSuchAlgorithmException(conProp.getProperty(Constants.CODE_DIGEST_ALGO_NOT_SUPPORTED));
		}
		return digestAlgoName;
	}

	public static String getSignatureAlgorithmUri(String algorithmMethod) throws Exception {

		String signAlgoUri = null;
		switch (algorithmMethod) {
		case "SHA1withRSA":
			signAlgoUri = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
			break;
		case "SHA224withRSA":
			signAlgoUri = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224;
			break;
		case "SHA256withRSA":
			signAlgoUri = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
			break;
		case "SHA384withRSA":
			signAlgoUri = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384;
			break;
		case "SHA512withRSA":
			signAlgoUri = org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512;
			break;
		default:
			throw new NoSuchAlgorithmException(conProp.getProperty(Constants.CODE_SIGNATURE_ALGO_NOT_SUPPORTED));
		}
		return signAlgoUri;
	}

	public static String getSignatureAlgorithm(String algorithmMethod) throws Exception {

		String signAlgoName = null;
		switch (algorithmMethod) {
		case "1":
			signAlgoName = "SHA256withRSA";
			break;
		case "2":
			signAlgoName = "SHA384withRSA";
			break;
		case "3":
			signAlgoName = "SHA512withRSA";
			break;
		default:
			throw new NoSuchAlgorithmException(conProp.getProperty(Constants.CODE_SIGNATURE_ALGO_NOT_SUPPORTED));
		}
		return signAlgoName;
	}

}
