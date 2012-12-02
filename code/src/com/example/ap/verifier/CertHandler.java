package com.example.ap.verifier;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.*;


public class CertHandler {
	
	X509Certificate certificate;
	X509Certificate ca;

	String set_certificate(X509Certificate cert, X509Certificate certAuthority)
	{
		
		certificate = cert;
		ca = certAuthority;
		
		// Verify time
		try {
			cert.checkValidity();
		} catch (CertificateExpiredException e) {
			return "Certificate Expired";
		} catch (CertificateNotYetValidException e) {
			return "Certificate Not Yet Valid";
		}
		
		try {
			cert.verify(ca.getPublicKey());
		} catch (InvalidKeyException e) {
			return "Invalid Key";
		} catch (CertificateException e) {
			return "Certificate Exception";
		} catch (NoSuchAlgorithmException e) {
			return "Invalid Certificate Algorithm";
		} catch (NoSuchProviderException e) {
			return "Invalid Certificate Provider";
		} catch (SignatureException e) {
			return "Invalid Certificate Signature";
		}
		
		return "Valid";
		
	}
	
	
	boolean verify_signature(byte[] shortString, byte[] signature)
	{
		
		PublicKey pubKeyRSA = certificate.getPublicKey();
		boolean res;
		Signature sig;
		try {
			sig = Signature.getInstance("SHA1withRSA", "FlexiCore");
		} catch (NoSuchAlgorithmException e1) {
			return false;
		} catch (NoSuchProviderException e1) {
			return false;
		}
		
		try {
			sig.initVerify(pubKeyRSA);
		} catch (InvalidKeyException e) {
			return false;
		}
		
		try {
			sig.update(shortString);
		} catch (SignatureException e1) {
			return false;
		}
		
		try {
			 res = sig.verify(signature);
		} catch (SignatureException e) {
			return false;
		}

		return res;
		
	}
}
