import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.asymmetric.X509;

public class CertificateListener extends Thread {

    private ObjectInputStream inputStream;
    private ObjectOutputStream outputStream;
    private PublicKey caPublic;
    private KeyStore keystore;
    private X509Certificate clientCertificate;
    private int noOfClients;

    public CertificateListener(ObjectInputStream inputStream, ObjectOutputStream outputStream, PublicKey caKey, KeyStore keystore, X509Certificate clientCertificate) {
        this.inputStream = inputStream;
        this.outputStream = outputStream;
        this.caPublic = caKey;
        this.keystore = keystore;
        this.clientCertificate = clientCertificate;
        this.noOfClients = 0;
    }
    public void run() {
        while(true){
            X509Certificate certificate = null;
            try {
                Object temp = this.inputStream.readObject();
                certificate = (X509Certificate) temp;
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
            try {
                synchronized(this.inputStream) {
                    //certificate.verify(this.caPublic);
                    noOfClients++;
                    
                }
            } catch (Exception e) {
                try{
                    System.out.println("Certification auth failed!");
                    this.outputStream.writeObject(false);
                } catch(Exception r){
                    r.printStackTrace();
                }
                e.printStackTrace();
            }
        }
    }
}
