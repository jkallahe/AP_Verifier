package com.example.ap.verifier;

import java.io.*;
import java.security.*;

import android.app.Activity;
import android.content.res.AssetManager;

public class StringComparison extends Activity{
public String getString()
{
	AssetManager manager = getAssets();
	byte[] digest = null;
	/* reading the cert file whose path is given as first argument */
	try {
	InputStream fis = manager.open("server.crt");
	
	int b;
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
	try {
		while((b= fis.read() ) >-1)
		{		
			outputStream.write( (byte) b);
		}
	} catch (IOException e1) {
		System.exit(-1);
	}
	 
	
	byte[] certBytes= outputStream.toByteArray( );
	fis.read(certBytes);
	MessageDigest certDigest = MessageDigest.getInstance("SHA-256");
	certDigest.update(certBytes);
	digest = certDigest.digest();
	fis.close();
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
	
	
	return output_str;
}
}
