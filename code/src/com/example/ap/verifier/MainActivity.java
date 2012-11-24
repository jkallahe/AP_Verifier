package com.example.ap.verifier;

import java.util.Arrays;
import java.util.List;

import com.example.ap.verifier.MifareClassicParser;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.view.Menu;

public class MainActivity extends Activity {
	
	private NfcAdapter adapter;
	private PendingIntent pendingIntent;	
	String[][]	techLists = new String[][] { new String[] { MifareClassic.class.getName() } };	
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        //NFC stuff
        adapter = NfcAdapter.getDefaultAdapter(this);
		pendingIntent = PendingIntent.getActivity(this, 0,
				new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);        
        Intent intent = getIntent();
        resolveIntent(intent);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_main, menu);
        return true;
    }
    
	public void resolveIntent(Intent intent)
	{
		String action = intent.getAction();
		Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG); //Why not getParcelableArrayExtra ??
	
		if(NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action))
		{
			//NDef Tag
		}
		else if(NfcAdapter.ACTION_TECH_DISCOVERED.equals(action))
		{
		    //Get tech list (tag type) from intent
		    String[] techList_array = tag.getTechList();
		    List<String> techList = Arrays.asList(techList_array);
		     
		    if(techList.contains("android.nfc.tech.MifareClassic"))
		    {
		    	MifareClassicParser mcp = new MifareClassicParser();
		    	String tagData = mcp.readMifareClassic(tag);
		    	tagData += "\n";
		    	
		    	//need to actually do something with the tag data
		    }
		}
	    else
	    {
	    	//if here, failed to recognize tag type supported by our app
	    }  
	}
	
	@Override
	public void onPause() {
		super.onPause();
		adapter.disableForegroundDispatch(this);
	}

	@Override
	public void onResume() {
		super.onResume();
		adapter.enableForegroundDispatch(this, pendingIntent, null, techLists);
	}	
}