package com.example.ap.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.util.Log;

import java.security.cert.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class MifareClassicParser 
{
	
	public MifareClassicParser()
	{
		
		
	}
	
	
	
	byte[] getSignature(String shortstring)
	{
		
		PrivateKey k = null;
		
		Signature s = null;
		try {
			s = Signature.getInstance("SHA1withRSA");
		} 
		catch (NoSuchAlgorithmException e1) {
			System.out.println("Problem signing");
			System.exit(1);;
		};
		try {
			s.initSign(k);
		} 
		catch (InvalidKeyException e) {
			System.out.println("Problem signing");
			System.exit(1);
		}
		
		try {
			s.update(shortstring.getBytes());
		} 
		catch (SignatureException e) {
			System.out.println("Problem signing");
			System.exit(1);
		}
		
		
		byte[] sig = null;
		try {
			sig = s.sign();
		} 
		catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return sig;
		
	}
	
	byte[] readCertificateBytes(File certfile)
	{
		FileInputStream inStream = null;
		try {
			inStream = new FileInputStream(certfile);
		} 
		catch (FileNotFoundException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		int len = (int) certfile.length();
		
		byte[] buff = new byte[len+1];
		
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
	
	public String getString(byte[] data)
	{
		String c = "";
		byte[] aggr = new byte[8];
		
		for(int i = 0; i < 8; i++){
			aggr[i] = data[i];
		}
		
		c = aggr.toString();
		
		return c;
		
	}
	
	public String getCert(byte[] data)
	{
		String res = "";
		
		String c = "";
		byte[] aggr = new byte[631];
		
		for(int i = 0; i < 631; i++){
			aggr[i] = data[8+64+i];
		}
		
		c = aggr.toString();
		
		return res;
		
	}
	
	public String getSig(byte[] data)
	{
		String res = "";
		
		String c = "";
		byte[] aggr = new byte[8];
		
		for(int i = 0; i < 64; i++){
			aggr[i] = data[8+i];
		}
		
		c = aggr.toString();
		
		return res;
		
	}

	//This is the code for reading MifareClassic cards, not sure if this actually works -GO 
	public String readMifareClassic(Tag tag)
    {    
    	  MifareClassic mfc = MifareClassic.get(tag);
          
          try {
	            mfc.connect();
	            boolean authenticate = false;
	            byte[] byteData = null;
	            String mfcData = "";
	            
	            //get the number of sectors the card has and loop through them
	            int numSectors = mfc.getSectorCount();
	            int numBlocks = 0;
	            int blockIndex = 0;
	            
	            for(int sector = 0; sector < numSectors; sector++) 
	            {
	                //authenticate the sector
	                authenticate = mfc.authenticateSectorWithKeyB(sector, MifareClassic.KEY_DEFAULT);	                
	                
	                if(authenticate)
	                {
	                    //get the block count in each sector
	                	numBlocks = mfc.getBlockCountInSector(sector);
	                	blockIndex = mfc.sectorToBlock(sector);
	                    for(int block = 0; block < numBlocks; block++) 
	                    {
	                    	if((sector == 0 && block == 0) || block == 3)
	                    	{
	                    		blockIndex++;
	                    		continue;
	                    	}
	                        //read the block
	                        byteData = mfc.readBlock(blockIndex);    
	                        blockIndex++;
	                        mfcData += new String(byteData);
	                    }
	                }
	                else // Authentication failed - Handle it
	                { 
	                	return "Failed to Authenticate";
	                }
	            }
	            
	            return mfcData;
          }
          catch(IOException e) { 
             	Log.e("Read MifareClassic", "IOException while reading tag", e);        	
            	return e.getLocalizedMessage();
          }
          finally {
        	  if (mfc != null) 
              {
            	  try 
            	  {
            		  mfc.close();
            	  }
            	  catch(Exception e)
            	  {
  	               		Log.e("Read MifareClassic", "Error closing tag...", e);
            	  }
              }
          }          
    }
}
