import java.io.*;
import java.util.*;

// class for encapsulating an encrypted and signed message
public class Message implements Serializable {

	public String recipientHash; // SHA-256 hash of recipient userid
	public Date timestamp;       // timestamp (java.util.Date)
	public byte[] key;           // AES key used, encrypted with RSA
	public byte[] iv;            // unencrypted IV
	public byte[] encryptedMsg;  // sender userid + message, encrypted with AES
	public byte[] signature;     // signature of all above
	
}
