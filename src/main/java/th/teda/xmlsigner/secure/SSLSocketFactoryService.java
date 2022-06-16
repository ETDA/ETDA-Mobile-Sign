package th.teda.xmlsigner.secure;


import th.teda.xmlsigner.GetProperties;
import th.teda.xmlsigner.configurations.Configurations;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Properties;


public class SSLSocketFactoryService {


    public SSLSocketFactory getSocketFactory() throws Exception {

        SSLSocketFactory sslSf = null;

        try {
            // Loading CAs from an InputStream
            Properties appProp = GetProperties.getPropertyFromPath(Configurations.configPath);
            String configPath = appProp.getProperty("configPath");
            Properties conProp = GetProperties.getPropertyFromPath(configPath);
            String filePathCA = conProp.getProperty("filePathCA");
            String pwdCA = conProp.getProperty("pwdCA");

            KeyStore ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(filePathCA);
            ks.load(fis, pwdCA.toCharArray());

            // We build the TrustManager (Server certificates we trust)
            TrustManagerFactory trustFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustFactory.init(ks);
            TrustManager[] tms = trustFactory.getTrustManagers();

            // We build a SSLContext with both our trust/key managers
            SSLContext sslContext = SSLContext.getInstance("TLS");
            // sslContext.init(km, tms, null);
            sslContext.init(null, tms, null);
            sslSf = sslContext.getSocketFactory();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return sslSf;
    }
}
