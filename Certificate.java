import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

public class Certificate{

    /**
    * Creates X509 certificate 
    * @param name Name used to identify certificate
    * @param publicKey Public key of client
    * @param caPrivateKey Private key of CA
    * @return
    */
    public static X509Certificate createCertificate(String name, Key publicKey, Key caPrivateKey) {
        try {
            X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Issuer CA"), // issuer
                BigInteger.valueOf(System.currentTimeMillis()) // serial number
                .multiply(BigInteger.valueOf(10)),
                new Date(System.currentTimeMillis() - 1000L * 5), // start time
                new Date(System.currentTimeMillis() + ExValues.THIRTY_DAYS), // expiry time
                new X500Name("CN=" + name), // subject
                (PublicKey) publicKey); // subject public key

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider("BC");
            return new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v3CertBldr.build(signerBuilder.build((PrivateKey) caPrivateKey)));
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    /**
    * 
    * @param caPair CA keypair
    * @param fileName Name of file to store certificates
    * @param pass Password used for store
    */
    public static void keyStore(KeyPair caPair, String fileName, char[] pass){
        try {
            X509Certificate certificate = createCertificate("CA", caPair.getPublic(), caPair.getPrivate());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setEntry("CA",
                                    new KeyStore.PrivateKeyEntry(caPair.getPrivate(),
                                    new X509Certificate[]{certificate}),
                                    new KeyStore.PasswordProtection(pass));
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            keyStore.store(bOut, pass);
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static void createCACertificate() {
        try {
            KeyPair keys = crypto.generateRSA();
            X509Certificate certificate = createCertificate("CA", keys.getPublic(), keys.getPrivate());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            KeyStore.Entry entry = new KeyStore.PrivateKeyEntry(keys.getPrivate(), new X509Certificate[]{certificate});
            keyStore.setEntry("CA", entry, new KeyStore.PasswordProtection("password".toCharArray()));
            FileOutputStream fs = new FileOutputStream(System.getProperty("user.dir") + "\\certificate.store");
            //System.getProperty("user.dir") + "\\certificate.store"
            keyStore.store(fs, "password".toCharArray());
            } catch (Exception e) {
                e.printStackTrace();
            }
    }

    public static void main(String[] args) {
        createCACertificate();
    }
}