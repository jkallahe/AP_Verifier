package com.example.ap.verifier;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetManager;

public class TagWriter extends Activity {
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_write_tag);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_about, menu);
		return true;
	}
	
    @Override  
    protected void onNewIntent(Intent intent) 
    {  
    	super.onNewIntent(intent);   
    	String action = intent.getAction();
        
        if(NfcAdapter.ACTION_TECH_DISCOVERED.equals(action))
        {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            
            //Get tech list (tag type) from intent
            String[] techList_array = tag.getTechList();
            
            //Print out tech list to screen
            String techList_string = "";
            for(String tech : techList_array)
            {
            	techList_string += tech;
            	techList_string += "\n";
            }
            
            List<String> techList = Arrays.asList(techList_array);
            
            if(techList.contains("android.nfc.tech.MifareClassic"))
            {
            	AssetManager manager = getAssets();
            	
            	String shortstring = getShortString();
            	byte[] sig = getSignature(shortstring);
            	byte[] cert = readCertificateBytes();
            	
            	ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            	try {
					outputStream.write( shortstring.getBytes() );
					outputStream.write( sig );
	            	outputStream.write(cert);
				} catch (IOException e) {
					System.exit(1);
					System.out.println("Failed to write byte array");
				}
            	

            	byte aggr[] = outputStream.toByteArray( );
            	
            	writeMifareClassic(tag, aggr);
            }  
        }
    }  	
    
    String getShortString()
	{
		String s = null;
		
		StringComparison c = new StringComparison();
		s = c.getString();
		
		return s;
	}
		
	byte[] getSignature(String shortstring)
	{
		AssetManager manager = getAssets();
		
		File pkfile = new File("/Users/neo/java/Laptop_sim/files/key.der");
		InputStream fis = null;
		try {
			fis = manager.open("key.pem");
		} catch (FileNotFoundException e) {
			System.exit(1);
		} catch (IOException e) {
			System.exit(1);
		}
		byte[] pkbytes = new byte[(int) pkfile.length()];
		try {
			fis.read(pkbytes);
		} catch (IOException e) {
			System.exit(1);
		}
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.exit(1);
		}
		KeySpec ks = new PKCS8EncodedKeySpec(pkbytes);
		RSAPrivateKey pk = null;
		try {
			pk = (RSAPrivateKey) keyFactory.generatePrivate(ks);
		} catch (InvalidKeySpecException e) {
			System.exit(1);
		}
		String msg = shortstring;
		Signature sigo = null;
		try {
			sigo = Signature.getInstance("SHA1withRSA");
		} catch (NoSuchAlgorithmException e) {
			System.exit(1);
		}
		try {
			sigo.initSign(pk);
		} catch (InvalidKeyException e) {
			System.exit(1);
		}
		try {
			sigo.update(msg.getBytes());
		} catch (SignatureException e) {
			System.exit(1);
		}
		byte[] signedmsg = null;
		try {
			signedmsg = sigo.sign();
		} catch (SignatureException e) {
			System.exit(1);
		}	
		
		try {
			fis.close();
		} catch (IOException e) {
			System.exit(1);
		}
		
		return signedmsg;
	}
	
	byte[] readCertificateBytes()
	{
		AssetManager manager = getAssets();
		
		InputStream inStream = null;
		try {
			inStream = manager.open("server.crt");
		} 
		catch (FileNotFoundException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		} catch (IOException e) {
			System.exit(1);
		}
				
		int b;
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			while((b= inStream.read() ) >-1)
			{		
				outputStream.write( (byte) b);
			}
		} catch (IOException e1) {
			System.exit(-1);
		}
		
		byte[] buff = outputStream.toByteArray( );
		
		try {
			inStream.read(buff);
		} 
		catch (IOException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		try {
			inStream.close();
		} 
		catch (IOException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		return buff;
		
	}
	
	X509Certificate readCertificate(File certfile)
	{
		FileInputStream inStream = null;
		try {
			inStream = new FileInputStream(certfile);
		} 
		catch (FileNotFoundException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		CertificateFactory cf = null;
		
		try {
			cf = CertificateFactory.getInstance("X.509");
		} 
		catch (CertificateException e1) {
			System.out.println("Certificate reading problem");
			System.exit(1);;
		}
		
		X509Certificate cert = null;
		
		try {
			cert = (X509Certificate)cf.generateCertificate(inStream);
		} 
		catch (CertificateException e1) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		try {
			inStream.close();
		} 
		catch (IOException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		return cert;
	}	
	
	public boolean writeMifareClassic(Tag tag, byte[] file)
	{
		MifareClassic mfc = MifareClassic.get(tag);
		FileInputStream fis = null;
		
		try
		{
			mfc.connect();
		 
		    
		    byte fileByte[] = new byte[16];
		    

		    int numSectors = mfc.getSectorCount();
		    int numBlocks = mfc.getBlockCountInSector(0);
		    int logicBlock;
		    
		    
		    // iterates the the sectors
		    for(int sector = 0,counter = 0; sector < numSectors; sector++, counter += 16) 
		    {
		    	// iterates through each block within a sector and writes that block
		    	for(int block=0; block < numBlocks; block++) 
		    	{
		    		logicBlock = mfc.sectorToBlock(sector) + block;
		    		
		    		for(int x = 0; x < 16; x++)
		    		{
		    			if(file.length < (counter+x))
		    			{
		    				fileByte[x] = file[counter+x];
		    			}
		    			else
		    			{
		    				fileByte[x] = (byte) 0;
		    			}
		    		}
		 
		    		if(sector == 0 && block == 0) 
		    			continue;
		    		
		        	mfc.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT);
		        	mfc.writeBlock(logicBlock, fileByte);
		        }
		    }
		    
		    return true;
		}
        catch(IOException e) { 
        	Log.e("Read MifareClassic", "IOException while reading tag", e);        	
        	return false;
        }
        finally {
        	if (fis != null) 
        	{
				try {
					fis.close();
				}
				catch(Exception e) {
					Log.e("Close File", "Error closing file...", e);
				}
        	}
        	
        	if (mfc != null) 
        	{
				try {
					mfc.close();
				}
				catch(Exception e) {
					Log.e("Write MifareClassic", "Error closing tag...", e);
				}
        	}        	
        }    
	}	
	
}
