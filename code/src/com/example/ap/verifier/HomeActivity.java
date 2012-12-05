package com.example.ap.verifier;


//import com.example.ap.comparison_strings.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.cert.CertificateException;
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
import com.example.ap.verifier.CertHandler.*;

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
            	byte[] tagData = mcp.readMifareClassic(tag);
            	System.out.println(tagData);
            	byte[] res = mcp.getString(tagData);
            	byte[] sig = mcp.getSig(tagData);
            	byte[] cert = mcp.getCert(tagData);
            	
            	Log.v(TAG, "Raw Data: " + tagData.length);
            	Log.v(TAG, "SSC: " + res);
            	Log.v(TAG, "SSC Length: " + res.length);
            	Log.v(TAG, "Signature: " + sig);
            	Log.v(TAG, "Signature Length: " + sig.length);
            	Log.v(TAG, "Cert: " + cert);
            	Log.v(TAG, "Cert Length: " + cert.length);
            	
            	try
            	{
	            	CertHandler c = new CertHandler();
	            	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	            	InputStream is = new ByteArrayInputStream(cert);
	            	X509Certificate x509 = (X509Certificate)cf.generateCertificate(is);
	            	c.set_certificate(x509);
	            	validity valid = c.check_valid_signature(res, sig);
	            	if(valid == validity.Valid)
	            	{
	                	TextView t = (TextView) findViewById(R.id.shortStringValue);
	                	String woohoo = new String(res);
	                	String ew = "Verified String: " + woohoo;
	                	t.setText(ew);
	            	}
	            	else
	            	{
	                	TextView t = (TextView) findViewById(R.id.shortStringValue);
	                	t.setText("Incorrect Certificate Signature");
	            	}
            	}
            	catch (CertificateException ce) 
            	{
					// TODO Auto-generated catch block
					ce.printStackTrace();
				}           
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
