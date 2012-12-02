package com.example.ap.verifier;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.*;


enum validity {Valid, Expired, NotYetValid, InvalidAlgorithm, InvalidKey, InvalidSignature, CertificateException};

public class CertHandler {
	
	X509Certificate certificate;

	/*
	 * Important: the return value of this function must be checked.  This 
	 * function validates the certificate and ensures it has been signed by
	 * the given certificate authority.
	 */
	validity set_certificate(X509Certificate cert)
	{
		
		certificate = cert;
		
		// Verify time
		// Future Work: Certificates are only self-signed
		try {
			cert.checkValidity();
		} catch (CertificateExpiredException e) {
			return validity.Expired;
		} catch (CertificateNotYetValidException e) {
			return validity.NotYetValid;
		}
		
		return validity.Valid;
		
	}
	
	
	validity check_valid_signature(byte[] shortString, byte[] signature)
	{
		
		PublicKey key = certificate.getPublicKey();
		Signature sig;
		
		try {
			sig = Signature.getInstance("SHA1withRSA");
		} catch (NoSuchAlgorithmException e1) {
			return validity.InvalidAlgorithm;
		}
		
		try {
			sig.initVerify(key);
		} catch (InvalidKeyException e) {
			return validity.InvalidKey;
		}
		
		try {
			sig.update(shortString);
		} catch (SignatureException e1) {
			return validity.InvalidSignature;
		}
		
		boolean valid;
		try {
			 valid = sig.verify(signature);
		} catch (SignatureException e) {
			return validity.InvalidSignature;
		}
		
		
		if(valid)
			return validity.Valid;
		else
			return validity.InvalidSignature;
		
	}
}
