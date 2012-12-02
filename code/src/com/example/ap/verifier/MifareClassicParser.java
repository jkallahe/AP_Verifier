package com.example.ap.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.util.Log;

public class MifareClassicParser 
{
	
	public MifareClassicParser()
	{
		
		
	}
	
	public boolean writeMifareClassic(Tag tag, File file)
	{
		MifareClassic mfc = MifareClassic.get(tag);
		FileInputStream fis = null;
		
		try
		{
			mfc.connect();
		 
		    fis = new FileInputStream(file);
		    byte fileByte[] = new byte[16];
		    

		    int numSectors = mfc.getSectorCount();
		    int numBlocks = mfc.getBlockCountInSector(0);
		    int logicBlock;
		    
		    // iterates the the sectors
		    for(int sector = 0; sector < numSectors; sector++) 
		    {
		    	// iterates through each block within a sector and writes that block
		    	for(int block=0; block < numBlocks; block++) 
		    	{
		    		logicBlock = mfc.sectorToBlock(sector) + block;
		    		fis.read(fileByte);
		 
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
	
	//This is the code for reading MifareClassic cards, not sure if this actually works -GO 
	public String readMifareClassic(Tag tag)
    {    
    	  MifareClassic mfc = MifareClassic.get(tag);
          
          try 
          {
	            mfc.connect();
	            boolean authenticate = false;
	            byte[] byteData = null;
	            String mfcData = null;
	            
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
	            
	            mfcData = mfcData.replaceAll("[^\\x20-\\x7e]", "");
	            return mfcData;
          }
          catch(IOException e) 
          { 
             	Log.e("Read MifareClassic", "IOException while reading tag", e);        	
            	return e.getLocalizedMessage();
          }
          finally 
          {
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
