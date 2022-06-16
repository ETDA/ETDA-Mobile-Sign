package th.teda.xmlsigner.utils;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.CRL;
//import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

//import org.bouncycastle.jce.X509LDAPCertStoreParameters;

public class GetCrlList {

	public GetCrlList() {

	}
	
	public List<CRL> readCRLsFromCert(X509Certificate cert)
	        throws Exception {
	    List<CRL> crls = new ArrayList<>();
	    
	    byte[] extVal = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
	    if (extVal == null)
			return crls;
	    
	    ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(extVal));
        ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
        DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;

        oAsnInStream.close();

        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2 = oAsnInStream2.readObject();
        
	    CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(derObj2);		
	    
	    DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();
	    
	    for (org.bouncycastle.asn1.x509.DistributionPoint o: distributionPoints) {
	    	DistributionPointName dpn = o.getDistributionPoint();
	        if (dpn != null) {
	        	if (dpn.getType() == DistributionPointName.FULL_NAME) {
	                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
	                for (GeneralName genName : genNames) {
	                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
	                        String url = DERIA5String.getInstance(genName.getName()).getString();
	                        for (CRL crl: loadCRLs(url)) {
		                        if (crl instanceof X509CRL) {
		                        	crls.add((X509CRL)crl);
		                        }
		                    }
		                    break;  // Different name should point to same CRL
	                    }
	                }
	            }
	        }
	    }
	    return crls;
	}
	
	public Collection<? extends CRL> loadCRLs(String src) throws Exception { 
        InputStream in = null; 
        URI uri = null; 
        if (src == null) { 
            in = System.in; 
        } else { 
            try { 
                uri = new URI(src); 
                if (uri.getScheme().equals("ldap")) { 
                    // No input stream for LDAP 
                } else { 
                    in = uri.toURL().openStream(); 
                } 
            } catch (Exception e) { 
                try { 
                    in = new FileInputStream(src); 
                } catch (Exception e2) { 
                    if (uri == null || uri.getScheme() == null) { 
                        throw e2;   // More likely a bare file path 
                    } else { 
                        throw e;    // More likely a protocol or network problem 
                    } 
                } 
            } 
        } 
        if (in != null) { 
            try { 
                // Read the full stream before feeding to X509Factory, 
                // otherwise, keytool -gencrl | keytool -printcrl 
                // might not work properly, since -gencrl is slow 
                // and there's no data in the pipe at the beginning. 
                ByteArrayOutputStream bout = new ByteArrayOutputStream(); 
                byte[] b = new byte[4096]; 
                while (true) { 
                    int len = in.read(b); 
                    if (len < 0) break; 
                    bout.write(b, 0, len); 
                } 
                return CertificateFactory.getInstance("X509").generateCRLs( 
                        new ByteArrayInputStream(bout.toByteArray())); 
            } finally { 
                if (in != System.in) { 
                    in.close(); 
                } 
            } 
        } else {
//        	// must be LDAP, and uri is not null 
//            String path = uri.getPath(); 
//            if (path.charAt(0) == '/') path = path.substring(1); 
//            X509LDAPCertStoreParameters params2 = new X509LDAPCertStoreParameters.Builder(
//                    path, "")
//                    .build();
//            CertStore s = CertStore.getInstance("CRL/LDAP", params2, "BC");
//            return s.getCRLs(null); 
        	return null;
        } 
    }
}