import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class compression {

    /**
    * Compresses message using ZIP
    * @param message Message to compress
    * @return byte[]
    */
    public static byte[] compressMessage(ComplexMessage message) {
        ByteArrayOutputStream bOutputStream = null;
        GZIPOutputStream gOutputStream = null;
        ObjectOutputStream objectOut = null;
        try {
            System.out.println("Before compression size: " + message.toString().getBytes().length + " bytes");
            bOutputStream = new ByteArrayOutputStream();
            gOutputStream = new GZIPOutputStream(bOutputStream);
            objectOut = new ObjectOutputStream(gOutputStream);
            objectOut.writeObject(message);
            objectOut.flush();
            objectOut.close();
            System.out.println("Compressed");
            byte[] temp = bOutputStream.toByteArray();
            System.out.println("After compression size: " + temp.toString().length() + " bytes");
            return temp;
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
            return null;
        }
    } 

    /**
    * Decompresses ZIPed messages
    * @param message Message to unZip
    * @return byte[]
    */
    public static ComplexMessage decompressMessage(byte[] message) {
        ByteArrayInputStream bIn = null;
        GZIPInputStream gInputStream = null;
        ObjectInputStream objectIn = null;
        try {
            bIn = new ByteArrayInputStream(message);
            gInputStream = new GZIPInputStream(bIn);
            objectIn = new ObjectInputStream(gInputStream);
            ComplexMessage temp = (ComplexMessage) objectIn.readObject();
            objectIn.close();
            System.out.println("Decompressed");
            return temp;
        }
        catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
            return null;
        }
    } 
}
