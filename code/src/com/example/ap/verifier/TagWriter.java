package com.example.ap.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.app.Activity;

public class TagWriter {
		
	byte[] getSignature(String shortstring)
	{
		
		PrivateKey k = null;
		Signature s = null;
		
		try {
			s = Signature.getInstance("SHA1withRSA");
		} catch (NoSuchAlgorithmException e1) {
			System.out.println("Problem signing");
			System.exit(1);;
		};
		try {
			s.initSign(k);
		} catch (InvalidKeyException e) {
			System.out.println("Problem signing");
			System.exit(1);
		}
		
		try {
			s.update(shortstring.getBytes());
		} catch (SignatureException e) {
			System.out.println("Problem signing");
			System.exit(1);
		}
		
		
		byte[] sig = null;
		try {
			sig = s.sign();
		} catch (SignatureException e) {
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
		} catch (FileNotFoundException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		int len = (int) certfile.length();
		
		byte[] buff = new byte[len+1];
		
		try {
			inStream.read(buff);
		} catch (IOException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		
		try {
			inStream.close();
		} catch (IOException e) {
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
		} catch (FileNotFoundException e) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1) {
			System.out.println("Certificate reading problem");
			System.exit(1);;
		}
		X509Certificate cert = null;
		try {
			cert = (X509Certificate)cf.generateCertificate(inStream);
		} catch (CertificateException e1) {
			System.out.println("Certificate reading problem");
			System.exit(1);
		}
		try {
			inStream.close();
		} catch (IOException e) {
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
        catch(IOException e) 
        { 
        	Log.e("Read MifareClassic", "IOException while reading tag", e);        	
        	return false;
        }
        finally 
        {
        	if (fis != null) 
        	{
				try 
				{
					fis.close();
				}
				catch(Exception e)
				{
					Log.e("Close File", "Error closing file...", e);
				}
        	}
        	
        	if (mfc != null) 
        	{
				try 
				{
					mfc.close();
				}
				catch(Exception e)
				{
					Log.e("Write MifareClassic", "Error closing tag...", e);
				}
        	}        	
        }    
	}	
	
}
