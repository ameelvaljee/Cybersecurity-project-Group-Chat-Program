import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;


public class server{
    private  ServerSocket serverSocket;
    public Integer joined = 0;
    public ArrayList<GroupMember> groupMembers;
    public Boolean authenticating;
    public KeyPair certAuthKeys;


    public server() throws IOException {
        serverSocket = new ServerSocket(8000);
        serverSocket.setSoTimeout(0);
        groupMembers = new ArrayList<>();
        loadKeysFromCertificate();
    }


    private void iniateServer() {

        try {
            while (!serverSocket.isClosed()) {
                System.out.println("Listening on " + serverSocket.getLocalPort());
                Socket clientSoc = serverSocket.accept();
                System.out.println("Client Connected");
                GroupMember grpMember = new GroupMember(clientSoc, this);
                Thread clientThread = new Thread(grpMember);
                clientThread.start();
                joined++;
            }
        }

        catch(IOException e){
            e.printStackTrace();
        }
    }

    public void groupMemberDisconnect(GroupMember member, Socket socket){
        try {
            socket.close();
            System.out.println("Group Member " + member.getName() + " has been removed by the server");
        }

        catch (IOException e){
            e.printStackTrace();
        }
    }

    public void close() throws IOException{

        if(!serverSocket.isClosed()){
            serverSocket.close();
        }
    }

    public static void main(String [] args) throws IOException {

        server s = new server();
        s.iniateServer();
        s.close();


    }

    public boolean validateMember(X509Certificate cert){

        try {
            cert.verify(certAuthKeys.getPublic());
            System.out.println("Certificate authorized.");
        }

        catch(Exception e){
            e.printStackTrace();
            System.out.println("Failed to valdiate client");
            return false;
        }

        return true;

    }

    private void loadKeysFromCertificate() {
        try {
            //what keystore
            KeyStore keyStore1 = KeyStore.getInstance("PKCS12");
            keyStore1.load(new FileInputStream(System.getProperty("user.dir") + "\\certificate.store"), "password".toCharArray());
            //"C:\\Users\\Alex\\My Drive\\University\\2022\\NIS\\NIS\\src\\certificate.store
            KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection("password".toCharArray());
            KeyStore.Entry entry = keyStore1.getEntry("CA", password);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            PublicKey CAPublicKey = privateKeyEntry.getCertificate().getPublicKey();
            PrivateKey CAPrivateKey = privateKeyEntry.getPrivateKey();
            certAuthKeys = new KeyPair(CAPublicKey, CAPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
