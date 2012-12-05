package com.example.ap.verifier;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.AssetManager;

public class TagWriter extends Activity {
	private static final String TAG = "TagWriter";
    private NfcAdapter mNfcAdapter;  
    private IntentFilter[] mWriteTagFilters;  
    private PendingIntent mNfcPendingIntent;   	
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_write_tag);
		
		mNfcAdapter = NfcAdapter.getDefaultAdapter(this);  
		mNfcPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP  
            | Intent.FLAG_ACTIVITY_CLEAR_TOP), 0);  
  
		IntentFilter techDetected = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);  
		
		// Intent filters for writing to a tag  
		mWriteTagFilters = new IntentFilter[] { techDetected };
		
        Intent intent = getIntent();
        resolveIntent(intent);  			
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_about, menu);
		
		return true;
	}
	
	@Override  
	protected void onResume() 
	{  
		super.onResume();  
		
		if(mNfcAdapter != null)
			mNfcAdapter.enableForegroundDispatch(this, mNfcPendingIntent, mWriteTagFilters, null);
	}

    @Override  
    protected void onPause() 
    {  
         super.onPause();  
         if(mNfcAdapter != null) 
        	 mNfcAdapter.disableForegroundDispatch(this);  
    }  
	
    protected void resolveIntent(Intent intent) 
    {  
    	//super.onNewIntent(intent);   
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
            Log.v(TAG, "all of techList_string: " + techList_string);
            Log.v(TAG, "techList: " + techList.toString());
            
            if(techList.contains("android.nfc.tech.MifareClassic"))
            {	
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
    
//    String getShortString()
//	{
//		String s = getString();
//		
//		return s;
//	}
		
	byte[] getSignature(String shortstring)
	{
		AssetManager manager = getAssets();
		
		InputStream fis = null;
		try {
			fis = manager.open("key.der");
		} catch (FileNotFoundException e) {
			System.exit(1);
		} catch (IOException e) {
			System.exit(1);
		}
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

		byte[] pkbytes = outputStream.toByteArray( );
		
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

		
		try
		{
			mfc.connect();
		 
		    
		    byte fileByte[] = new byte[16];
		    

		    int numSectors = mfc.getSectorCount();
		    int numBlocks = mfc.getBlockCountInSector(0);
		    int logicBlock;
		    
		    
		    // iterates the the sectors
		    for(int sector = 0,counter = 0; sector < numSectors; sector++) 
		    {
		    	// iterates through each block within a sector and writes that block
		    	for(int block=0; block < numBlocks; block++, counter += 16) 
		    	{
		    		logicBlock = mfc.sectorToBlock(sector) + block;
		    		
		    		if((sector == 0 && block == 0)|| block == 3)
		    		{
		    			counter -=16;
		    			continue;
		    		}
		    		
		    		for(int x = 0; x < 16; x++)
		    		{
		    			if(file.length > (counter+x))
		    			{
		    				fileByte[x] = file[counter+x];
		    			}
		    			else
		    			{
		    				fileByte[x] = (byte) 0;
		    			}
		    		}
		 
		    		
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
        catch(Exception e) { 
        	Log.e("Read MifareClassic", "IOException while reading tag", e);        	
        	return false;
        }		
        finally {       
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

	public String getShortString()
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
