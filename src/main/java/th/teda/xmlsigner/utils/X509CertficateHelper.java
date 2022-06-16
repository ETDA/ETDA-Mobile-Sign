package th.teda.xmlsigner.utils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.encoders.Base64;

public class X509CertficateHelper {
	public static X509Certificate convertBase64toX509(String certString) throws Exception {
		// Convert base64 string to certificate
		CertificateFactory fact = null;
		try {
			fact = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw e;
		}

		byte[] certEncoded = Base64.decode(certString.getBytes());
		ByteArrayInputStream inputStream = new ByteArrayInputStream(certEncoded);
		X509Certificate cert = null;

		try {
			cert = (X509Certificate) fact.generateCertificate(inputStream);
		} catch (CertificateException e) {
			throw e;
		}
		// End Convert base64 string to certificate
		return cert;
	}


}
