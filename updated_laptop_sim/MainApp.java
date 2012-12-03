import java.io.*;
import java.security.*;

public class MainApp {
public static void main(String args[])
{
	byte[] digest = null;
	/* reading the cert file whose path is given as first argument */
	File certFile = new File(args[0]);
	try {
	FileInputStream fis = new FileInputStream(certFile);
	byte[] certBytes= new byte[(int) certFile.length()];
	fis.read(certBytes);
	MessageDigest certDigest = MessageDigest.getInstance("SHA-256");
	certDigest.update(certBytes);
	digest = certDigest.digest();
	}
	catch(Exception e)
	{
		System.out.println("Exception Occured");
		System.exit(1);
	}
	
	String hash_val = new java.math.BigInteger(1, digest).toString(16);
	
	//hash_val = "d135bb84d0439dbaca32247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"; //SHA-3 hash
	
	Ssc ssc = new Ssc();
	

	/* Get certificate from wherever */
	
	/* Create hash value */
	String output_str = ssc.get_comparison_string(hash_val);
	System.out.print("User display string is "+output_str); //display SSC on screen
}
}
