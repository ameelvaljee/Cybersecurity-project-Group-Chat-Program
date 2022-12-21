import java.io.Serializable;
import java.security.cert.X509Certificate;

public class ComplexMessage implements Serializable{
    public String alias;
    public X509Certificate certificate;
    public String message;
    public byte[] byteMessage;
    public byte[] signedHash;
    public byte[] sharedKey;

    public ComplexMessage(String alias, X509Certificate certificate){
        this.alias = alias;
        this.certificate = certificate;
    }
    public ComplexMessage(String message) {
        this.message = message;
    }
    public ComplexMessage(String message, byte[] hash, String alias) {
        this.message = message;
        this.signedHash = hash;
        this.alias = alias;
    }
    public ComplexMessage(byte[] byteMessage, byte[] sharedKey, String alias) {
        this.byteMessage = byteMessage;
        this.sharedKey = sharedKey;
        this.alias = alias;
    }
}