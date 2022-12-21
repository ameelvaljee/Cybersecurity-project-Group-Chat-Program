import java.net.*;
import java.io.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import javax.crypto.SecretKey;

public class GroupMember extends Thread{
    private Socket clientSocket;
    public ObjectInputStream in;
    public  ObjectOutputStream out;
    private static volatile ArrayList<GroupMember> allGrpMembers = new ArrayList<>();
    public static volatile ArrayList<X509Certificate> grpMemberCerts = new ArrayList<>();
    private  server severRef;
    private X509Certificate cert;
    public String memberName;
    private SecretKey sessionKey;
    //private  String memberName;

    public GroupMember(Socket clientSocket, server severRef){

        try {
            this.clientSocket = clientSocket;
            in = new ObjectInputStream(clientSocket.getInputStream());
            out = new ObjectOutputStream(clientSocket.getOutputStream());
            memberName = "";
            //allGrpMembers.add(this);
            //System.out.println(allGrpMembers.size());
            this.severRef = severRef; //To reference data structures in the server

        }

        catch(Exception e){
            e.printStackTrace();
        }
    }

    public void run(){
        try {
            ComplexMessage initialMsg = (ComplexMessage) in.readObject();
            memberName = (String) initialMsg.alias;
            Boolean result = severRef.validateMember(initialMsg.certificate);
            if(!result) {
                severRef.groupMemberDisconnect(this, clientSocket);
                System.exit(0);
             }

            else if(result){
                sendSessionKey(initialMsg.certificate);
                allGrpMembers.add(this);
                grpMemberCerts.add(initialMsg.certificate);
                X509Certificate[] temp = new X509Certificate[grpMemberCerts.size()];
                broadcastCertificates(grpMemberCerts.toArray(temp));
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
        try {
                while (clientSocket.isConnected()) {
                    if(allGrpMembers.size() >= 2) {
                        System.out.println("More than 2 clients joined. Chat Started!");
                        Object message = in.readObject();
                        //System.out.println(new String(crypto.decryptMessageAES(sessionKey, (byte[]) message), "UTF-8"));
                        broadCast(message);
                    }
                }
                severRef.groupMemberDisconnect(this, clientSocket);
        }
            catch(Exception e){
                e.printStackTrace();
            }
    }

    public void sendSessionKey(X509Certificate certificate) {
        try {
            sessionKey = crypto.generateAES();
            System.out.println(sessionKey.getEncoded());
            out.writeObject(crypto.encryptRSA(certificate.getPublicKey(), sessionKey.getEncoded()));
            out.flush();
            System.out.println("Session key sent to " + memberName + "!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void outPutSharedKeyNotifier(Object message){

        try {
            out.writeObject(message);
            System.out.println("shared key distrubtion request to " + allGrpMembers.get(0));

            //System.out.println(message + "s");
        }

        catch(IOException e){
            e.printStackTrace();
        }
    }

    public void outPutMessage(Object message){

        try {
            out.writeObject(crypto.encryptMessageAES(sessionKey, (crypto.serialize(message))));
            out.flush();
            System.out.println("Broadcast message to all clients");

            //System.out.println(message + "s");
        }

        catch(IOException e){
            e.printStackTrace();
        }
    }

    public void outPutCertificate(X509Certificate cert){

        try {
            out.writeObject(cert);
//            out.newLine();
//            out.flush();
            //System.out.println(message + "s");
        }

        catch(IOException e){
            e.printStackTrace();
        }
    }

    public void broadcastCertificates(Object message){

        for(GroupMember i : allGrpMembers){
                System.out.println("Certificate sent to " + i.memberName);
                i.outPutMessage((message));
        }
        System.out.println("Certificates sent to all groupmembers.");
    }

    public void broadCast(Object message){
        try {
            byte[] temp = crypto.decryptMessageAES(sessionKey, (byte[]) message);
            ComplexMessage complexMessage = crypto.deserialize(temp);
            for(GroupMember i : allGrpMembers){
                if(complexMessage.alias.equals(("CN=" + i.memberName))) {
                    i.outPutMessage(complexMessage);
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public X509Certificate getCert(){
        return cert;
    }

    public Object waitForSharedKey(){
        System.out.println("Waiting for shared key");

        Object sharedKey = null;
        try {
            sharedKey = in.readObject();
            System.out.println("Recieved sharedKey");
        }

        catch (Exception e){
            System.out.println("Couldn't receive sharedkey");
            e.printStackTrace();
        }
        return sharedKey;
    }

    private Object sendSharedKey(){
        GroupMember distributer = allGrpMembers.get(0);
        distributer.outPutSharedKeyNotifier("sharedKey");
        Object sharedKey = distributer.waitForSharedKey();
        return sharedKey;



    }

//    private void broadcastCertificate(){
//
//        for(GroupMember i : allGrpMembers){
//            outPutCertificate(i);
//
//        }
//
//    }




}
