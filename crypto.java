import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

class crypto {
   
   /**
    * Generates a keypair using the RSA algorithm.
    * @return KeyPair
    */
   public static KeyPair generateRSA() {
      try{
         SecureRandom random = SecureRandom.getInstanceStrong();
         KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
         generator.initialize(1024, random); //2048
         KeyPair pair = generator.generateKeyPair();
         System.out.println("Generated RSA key pair");
         return pair;
      } catch(Exception e){
         e.printStackTrace();
         return null;
      }
   }

   /**
    * Encrypts a string message using an RSA key.
    * @param key  key used for encryption
    * @param message message to encrypt
    * @return byte[]
    */
   public static byte[] encryptRSA(Key key, String message) {
      byte[] input = message.getBytes();
      return encryptRSA(key, input);
   }

   /**
    * Encrypts a string message using an RSA key and PKCS1 padding.
    * @param key  key used for encryption
    * @param message message to encrypt
    * @return byte[]
    */
   public static byte[] encryptRSA(Key key, byte[] message) {
      try{
         Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
         cipher.init(Cipher.ENCRYPT_MODE, key);
         byte[] cipherText = cipher.doFinal(message);
         return cipherText;
      } catch(Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   /**
    * Decrypts a message using RSA padded with PKCS1
    * @param key key used to decrypt
    * @param message message to decrypt
    * @return byte[]
    */
   public static byte[] decryptRSA(Key key, byte[] message) {
      try{
         Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
         cipher.init(Cipher.DECRYPT_MODE, key);
         byte[] plainText = cipher.doFinal(message);
         return plainText;
      } catch(Exception e) {
         e.printStackTrace();
         return null;
      }
   }

   /**
    * Creates an AES secretkey
    * @return SecretKey
    */
   public static SecretKey generateAES() {
      try{
         SecureRandom random = SecureRandom.getInstanceStrong();
         KeyGenerator keyGen = KeyGenerator.getInstance("AES");
         keyGen.init(256, random);
         SecretKey key = keyGen.generateKey();
         System.out.println("Generated AES key");
         return key;
      } catch(Exception e){
         System.out.println("Couldn't generate AES key");
         e.printStackTrace();
         return null;
      }
   }

   /**
    * Encrypts a message with an AES key
    * @param key  Key used to encrypt
    * @param message messsage to encrypt
    * @return byte[]
    */
   public static byte[] encryptMessageAES(SecretKey key, byte[] message) {
      try{
         
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");
         cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
         byte[] cipherText = cipher.doFinal(message);
         return cipherText;
      } catch(Exception e) {
         System.out.println("Couldn't encrypt with AES key");
         e.printStackTrace();
         return null;
      }
   }

   /**
    * Decrypts message encrypted with AES key.
    * @param key Key used to 
    * @param message Message to decrypt
    * @return String
    */
   public static byte[] decryptMessageAES(SecretKey key, byte[] message) {
      try{
         byte[] iv = Hex.decode("9f741fdb5d8845bdb48a94394e84f8a3");
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
         byte[] plainText = cipher.doFinal(message);
         return plainText;
      } catch(Exception e) {
         System.out.println("Couldn't decrypt with AES key");
         e.printStackTrace();
         return null;
      }
   }

  /**
    * Hashed an input with SHA512
    * @param input Input to hash
    * @return byte[]
    */
  public static byte[] createHash(byte[] input) {
     try {
         MessageDigest hash = MessageDigest.getInstance("SHA512");
         byte[] temp = hash.digest(input);
         System.out.println("Hashed message with SHA512");
         return temp;
     } catch (Exception e) {
         System.out.println("Couldn't hash message with SHA512");
         e.printStackTrace();
         return null;
     }
  }

  /**
    * Creates a message that conforms to PGP standards
    * @param message Message to encode
    * @param privateKey RSA key used to encrypt. Asymetric key
    * @param secretKey key used for AES encryption. Shared key
    * @return byte[]
    */
  public static byte[] createPGPMessagePart1(String message, Key privateKey, String creator) {
     byte[] messageBytes = message.getBytes();
     System.out.println("Creating PGP message from: " + message);
     byte[] temp = encryptRSA(privateKey, createHash(messageBytes));
     System.out.println("Encrypted hash with private key");
     ComplexMessage complexMessage = new ComplexMessage(message, temp, creator);
     byte[] compressedMessage = compression.compressMessage(complexMessage);
     return compressedMessage;
  }

  public static ComplexMessage createComplexMessagePart2(byte[] message, Key publicKey, String aliasToSendTo) {
      SecretKey sharedKey = generateAES();
      byte[] secretEncryptedMessage = encryptMessageAES(sharedKey, message);
      System.out.println("Encrypted message with shared key");
      byte[] temp = encryptRSA(publicKey, sharedKey.getEncoded());
      System.out.println("Encrypted shared key with clients public key");
      ComplexMessage complexMessagetoSend = new ComplexMessage(secretEncryptedMessage, temp, aliasToSendTo);
      return complexMessagetoSend;
  }

  /**
    * Unpacks message that conforms to PGP standards.
    * @param message Message to decode
    * @param privateKey Key used to decrypt RSA encryption
    * @param publicKey Key used to decrypt AES encryption
    * @return String
    */
  public static ComplexMessage unpackPGPMessage(ComplexMessage message, Key privateKey){
      System.out.println("Decrypting PGP message");
      SecretKey sharedKey = new SecretKeySpec(decryptRSA(privateKey, message.sharedKey), "AES");
      System.out.println("Decrypted incoming shared key with private key");
      byte[] compressedMessage = decryptMessageAES(sharedKey, message.byteMessage);
      System.out.println("Decrypt incoming message with shared key");
      ComplexMessage messageAndHash = compression.decompressMessage(compressedMessage);
      return messageAndHash;
      /*if(name.equals(messageAndHash.alias)) {
         if(verifySignature(messageAndHash, publicKey)){
            return messageAndHash.message;
         } else{
            return null;
         }
      } else{
         return null;
      }*/
  }

  /**
    * Used to verify hashed message
    * @param message Message to verify
    * @return boolean
    */
   public static boolean verifySignature(ComplexMessage message, Key publicKey) {
      byte[] tempHash = createHash(message.message.getBytes());
      byte[] temp = decryptRSA(publicKey, message.signedHash);
      if(Arrays.equals(tempHash, temp)){
         System.out.println("Successful signature on hash");
         return true;
      } else {
         System.out.println("Signature Failed");
         return false;
      }
   }  

   /**
    * Turns object into bytes
    * @param obj Object to convert
    * @return byte[]
    */
  public static byte[] serialize(Object obj) {
     try {
         ByteArrayOutputStream out = new ByteArrayOutputStream();
         ObjectOutputStream os = new ObjectOutputStream(out);
         os.writeObject(obj);
         return out.toByteArray();
     } catch (Exception e) {
         System.out.println(e);
         return null;
     }
}

   /**
       * Used to turn bytes into ComplexMessage
      * @param data Byte[] representing ComplexMessage
      * @return ComplexMessage
      */
   public static ComplexMessage deserialize(byte[] data) throws IOException, ClassNotFoundException, ClassCastException{
      ByteArrayInputStream in = new ByteArrayInputStream(data);
      ObjectInputStream is = new ObjectInputStream(in);
      return (ComplexMessage) is.readObject();

   }

   /**
    * Used to turn bytes into ComplexMessage
   * @param data Byte[] representing ComplexMessage
   * @return ComplexMessage
   */
   public static X509Certificate[] deserializeByte(byte[] data) throws IOException, ClassNotFoundException, ClassCastException{
         ByteArrayInputStream in = new ByteArrayInputStream(data);
         ObjectInputStream is = new ObjectInputStream(in);
         return (X509Certificate[]) is.readObject();

   }
}
