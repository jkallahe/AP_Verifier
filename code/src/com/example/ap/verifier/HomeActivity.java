package com.example.ap.verifier;


//import com.example.ap.comparison_strings.*;

import java.io.InputStream;
import java.io.StringReader;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class HomeActivity extends Activity {
	private static final String TAG = "HomeActivity";
    private NfcAdapter mNfcAdapter;  
    private IntentFilter[] mReadTagFilters;  
    private PendingIntent mNfcPendingIntent;   
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_home);
		
		mNfcAdapter = NfcAdapter.getDefaultAdapter(this);  
		mNfcPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP  
            | Intent.FLAG_ACTIVITY_CLEAR_TOP), 0);  
  
		IntentFilter techDetected = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);  
		
		// Intent filters for writing to a tag  
		mReadTagFilters = new IntentFilter[] { techDetected };
		
        Intent intent = getIntent();
        resolveIntent(intent);
		
		Button buttonCalc = (Button) findViewById(R.id.calculate);
        buttonCalc.setOnClickListener(new OnClickListener()
        {
     	   public void onClick(View v){
     		   //ssc s = new ssc();
     		   //String comparison = s.get_comparison_string();
     		   //TextView text = (TextView) findViewById(R.id.shortStringValue);
     		   //text.setText(comparison);
     		   }
     	   }
        );
        
        Button buttonWriteTag = (Button) findViewById(R.id.writeTag);
        buttonWriteTag.setOnClickListener(new OnClickListener()
        {
     	   public void onClick(View v){
     		   //byte[] file = null;
     		   //Tag tag = null;
     		   //TagWriter m = new TagWriter(); 		   
     		   
     		   //m.writeMifareClassic(tag, file);
     		   Intent i = new Intent(HomeActivity.this, TagWriter.class); 
     		   startActivity(i);
     	   }
        }
        );
        
        Button buttonAbout = (Button) findViewById(R.id.about);
        buttonAbout.setOnClickListener(new OnClickListener()
        {
     	   public void onClick(View v){
     		   Intent i = new Intent(HomeActivity.this, About.class); 
     		   startActivity(i);
     		   }
     	   }
        );
	}

	@Override  
	protected void onResume() 
	{  
		super.onResume();  
		
		if(mNfcAdapter != null)
			mNfcAdapter.enableForegroundDispatch(this, mNfcPendingIntent, mReadTagFilters, null);
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
        	System.out.println("We have a tag");
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
            	MifareClassicParser mcp = new MifareClassicParser();
            	String tagData = mcp.readMifareClassic(tag);
            	byte[] tmp = tagData.getBytes();
            	String res = mcp.getString(tmp);
            	String sig = mcp.getSig(tmp);
            	String cert = mcp.getCert(tmp);
            	
            	/*CertHandler c = new CertHandler();
            	CertificateFactory cf = CertificateFactory.getInstance("X.509");
            	InputStream inputSource = new InputStream( new StringReader( cert) );
            	X509Certificate x = (X509Certificate)cf.generateCertificate(cert);*/
            	
            	TextView t = (TextView) findViewById(R.id.shortStringValue);
            	t.setText(res);
            	
            }  
        }
    }      
			
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.activity_home, menu);
		return true;
	}

}
