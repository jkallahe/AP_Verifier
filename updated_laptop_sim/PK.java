import java.io.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.security.*;
import java.math.BigInteger;

public class PK {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		/* convert a PEM key file to a .der format using the following openssl command:
		 * openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der
		 */
		File pkfile = new File("/Users/neo/java/Laptop_sim/files/key.der");
		FileInputStream fis = new FileInputStream(pkfile);
		byte[] pkbytes = new byte[(int) pkfile.length()];
		fis.read(pkbytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec ks = new PKCS8EncodedKeySpec(pkbytes);
		RSAPrivateKey pk = (RSAPrivateKey) keyFactory.generatePrivate(ks);
		String msg = "hey sign this";
		Signature sigo = Signature.getInstance("SHA1withRSA");
		sigo.initSign(pk);
		sigo.update(msg.getBytes());
		byte[] signedmsg = sigo.sign();	
		System.out.println("The signed message: " + new BigInteger(1,signedmsg).toString(16));
	}

}
