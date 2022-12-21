import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class MessageSender extends Thread {
    
    public static ObjectOutputStream objectOutputStream;
    public Client client;
    private Scanner sin;

    public MessageSender(ObjectOutputStream outputStream, Client client, Scanner sin) {
        this.sin = sin;
        objectOutputStream = outputStream;
        this.client = client;
    }

    public void run() {
        while(true){
            try {
                String temp = sin.nextLine();
                System.out.println(client.name + ": " + temp);
                send(temp, client);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    /**
    * Sends a session encrypted message to the server
    * @param temp String to send to server
    * @param client Client to send the message from
    */
    public static void send(String message, Client client) {
        byte[] toSend = crypto.createPGPMessagePart1(message, client.getPrivateKey(), client.name);
        try {
            for(X509Certificate x : client.publicCertificates) {
                    if(!x.equals(client.getclientCertificate())) {
                        ComplexMessage temp = crypto.createComplexMessagePart2(toSend, x.getPublicKey(), x.getSubjectX500Principal().getName());
                        objectOutputStream.writeObject(crypto.encryptMessageAES(client.getSessionKey(), crypto.serialize(temp)));
                        objectOutputStream.flush();
                    }
                }
                System.out.println("Sent message to clients");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
    * Sends a session encrypted ComplexMessage to the server from the client
    * @param temp The ComplexMessage to send to the server
    * @param client Client to send the message from
    */
    public static void send(ComplexMessage temp, Client client) {
        try {
            objectOutputStream.writeObject(crypto.encryptMessageAES(client.getSessionKey(), crypto.serialize(temp)));
            objectOutputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
