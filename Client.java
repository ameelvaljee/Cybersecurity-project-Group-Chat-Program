import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Client {

    private KeyPair caKeys;
    private final KeyPair rsaKeys;
    private SecretKey sessionKey;
    public final String name;
    private KeyStore keyStore; //probaly better to save in a keystore
    private ObjectOutputStream outputStream;
    private ObjectInputStream inputStream;
    private X509Certificate clientCertificate;
    public int noOfClients;
    public X509Certificate[] publicCertificates;
    private Scanner sin;

    public Client(String name, String IP, Scanner sin) {
        this.sin = sin;
        this.noOfClients = 0;
        this.rsaKeys = crypto.generateRSA();
        this.name = name;

        this.loadcaKeysFromCertificate();
        this.createClientCertificate();
        this.connectToServer(IP);
        this.registerWithServer();
        new MessageSender(this.outputStream, this, this.sin).start();
        this.startMessageReceiver();
    }

    /**
    * Handles incoming client messages
    */
    public void startMessageReceiver() {
        while(true) {
            try {
                Object message = this.inputStream.readObject();
                if(message instanceof byte[]) {
                    //System.out.println(new String(crypto.decryptMessageAES(sessionKey, (byte[]) message), "UTF-8"));
                    System.out.println("Received message");
                    byte[] temp = (crypto.decryptMessageAES(sessionKey, (byte[]) message));
                    System.out.println("Decrypted message with session key");
                    //System.out.println(temp.getClass());
                    try {
                        this.publicCertificates = crypto.deserializeByte(temp);
                        System.out.println("Received new certificates from server");
                    } catch(Exception e) {
                        try {
                            decipherMessage(crypto.deserialize(temp));
                        } catch (Exception x) {
                            x.printStackTrace();
                        }
                    }
                } 
                else {
                    System.out.println("Incoming message not recognized!");
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Message read error!");
            }
        }
    }

    public void decipherMessage(ComplexMessage message) {
        ComplexMessage uncompressedMessage = crypto.unpackPGPMessage(message, this.getPrivateKey());
        for(X509Certificate x : publicCertificates) {
            if(x.getSubjectX500Principal().getName().substring(3).equals(uncompressedMessage.alias)){
                if(crypto.verifySignature(uncompressedMessage, x.getPublicKey())){
                    System.out.println(x.getSubjectX500Principal().getName().substring(3) + ": " + uncompressedMessage.message);
                    return;
                }
            } else{
                System.out.println("No certificate to validate message");
            }
        }
    }

    public X509Certificate getclientCertificate() {
        return clientCertificate;
    }

    public PublicKey getPublicKey() {
        return rsaKeys.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return rsaKeys.getPrivate();
    }

    public SecretKey getSessionKey() {
        return this.sessionKey;
    }

    /**
    * Creates a client certificate with its public key signed by the ca.
    */
    public void createClientCertificate() {
        try {
            clientCertificate = Certificate.createCertificate(this.name, rsaKeys.getPublic(), caKeys.getPrivate());
            System.out.println("Created client certificate");
        } catch (Exception e) {
            System.out.println("Couldn't create client certificate!");
            e.printStackTrace();
            System.exit(0);
        }
    }

    /**
    * Loads pre generated keys for the certificate authority.
    */
    public void loadcaKeysFromCertificate() {
        try {
            //what keystore
            KeyStore keyStore1 = KeyStore.getInstance("PKCS12");
            keyStore1.load(new FileInputStream(System.getProperty("user.dir") + "\\certificate.store"), "password".toCharArray());/////////////////////////////////////////
            KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection("password".toCharArray());
            KeyStore.Entry entry = keyStore1.getEntry("CA", password);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PublicKey CAPublicKey = privateKeyEntry.getCertificate().getPublicKey();
            PrivateKey CAPrivateKey = privateKeyEntry.getPrivateKey();
            this.caKeys = new KeyPair(CAPublicKey, CAPrivateKey);
            System.out.println("Loaded CA keys from file certificate.store");
        } catch (Exception e) {
            System.out.println("Couldn't load CA keys from certificate.store");
            e.printStackTrace();
            System.exit(0);
        }
    }

    /**
    * Registers the clients name and certificate with the server.
    */
    public void registerWithServer() {
        try {
            this.outputStream.writeObject((Object)new ComplexMessage(this.name, this.clientCertificate));
            this.outputStream.flush();
            System.out.println("Sent client name and certificate to server");
            byte[] temp = (byte[]) this.inputStream.readObject();
            System.out.println("Registered with server");
            this.sessionKey = new SecretKeySpec(crypto.decryptRSA(rsaKeys.getPrivate(), temp), 0, 32, "AES") ;
            System.out.println("Received session key");
        } catch (Exception e) {
            System.out.println("Couldn't register with server!");
            e.printStackTrace();
            System.exit(0);
        }
    }

   /**
    * Connects the client to the server
    * @param serverIP IP of the server to connect to
    */
    public void connectToServer(String serverIP) {
        try {
            Socket socket = new Socket(serverIP, 8000);
            outputStream = new ObjectOutputStream(socket.getOutputStream());
            inputStream = new ObjectInputStream(socket.getInputStream());
            System.out.println("Connected to the server");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to connect to the server!");
            System.exit(0);
        }
    }
    public static void main(String[] args) {
        System.out.println("Starting client...");
        System.out.println("Please enter a username: ");
        Scanner sin = new Scanner(System.in);
        String userName = "";
        try {
            userName = sin.nextLine();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if(args.length != 0){
            Client client = new Client(userName, args[0], sin);
        }else {
            Client client = new Client(userName, "localhost", sin);
        }
    }
}