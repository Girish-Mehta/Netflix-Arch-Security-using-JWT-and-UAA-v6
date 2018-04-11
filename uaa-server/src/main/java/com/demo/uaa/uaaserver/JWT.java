package com.demo.uaa.uaaserver;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JWT {

	@Autowired
	UserInformationProxy userProxy;

	@PostMapping("/token")
	public String createJwtToken(@RequestBody UserInformation loginInfoInBody) {
		String retrievedInformation = userProxy.getUserInformationn(loginInfoInBody);
		RsaJsonWebKey rsaJsonWebKey = null;
		JsonWebKey jwk = null;
		String [] data = retrievedInformation.split(",");
		String uname=data[0];
		String role = data[1];
		if (role == null && uname == null)
			return null;

		// Create a new Json Web Encryption object
		JsonWebEncryption senderJwe = new JsonWebEncryption();
		try {
			rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
		} catch (JoseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Give the JWK a Key ID (kid), which is just the polite thing to do
		rsaJsonWebKey.setKeyId("k1");

		// Create the Claims, which will be the content of the JWT
		JwtClaims claims = null;

		// Create the Claims, which will be the content of the JWT
		claims = new JwtClaims();
		claims.setIssuer("Issuer"); // who creates the token and signs it
		claims.setAudience("Audience"); // to whom the token is intended to be sent
		claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
		claims.setSubject(role); // the subject/principal is whom the token is about
		claims.setClaim("username", uname); // additional claims/attributes about the subject can be added

		// A JWT is a JWS and/or a JWE with JSON claims as the payload.
		// In this example it is a JWS so we create a JsonWebSignature object.
		JsonWebSignature jws = new JsonWebSignature();

		// The payload of the JWS is JSON content of the JWT Claims
		jws.setPayload(claims.toJson());

		// The JWT is signed using the private key
		jws.setKey(rsaJsonWebKey.getPrivateKey());

		// Set the Key ID (kid) header because it's just the polite thing to do.
		// We only have one key in this example but a using a Key ID helps
		// facilitate a smooth key rollover process
		jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

		// Set the signature algorithm on the JWT/JWS that will integrity protect the
		// claims
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// Sign the JWS and produce the compact serialization or the complete JWT/JWS
		// representation, which is a string consisting of three dot ('.') separated
		// base64url-encoded parts in the form Header.Payload.Signature
		// If you wanted to encrypt it, you can simply set this jwt as the payload
		// of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
		String jwt = null;
		String jwkJson = null;
		try {
			jwt = jws.getCompactSerialization();
			// The shared secret or shared symmetric key represented as a octet sequence
			// JSON Web Key (JWK)
			jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
			jwk = JsonWebKey.Factory.newJwk(jwkJson);
		} catch (JoseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// A JSON string with only the public key info
		String publicKeyJwkString = rsaJsonWebKey.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
		senderJwe.setPlaintext(publicKeyJwkString + "\nJWT:" + jwt);
		System.out.println("New String:" + publicKeyJwkString);

		// The plaintext of the JWE is the message that we want to encrypt.
		// senderJwe.setPlaintext(rsaJsonWebKey.getKey().toString() + "\nJWT:" + jwt);

		// Set the "alg" header, which indicates the key management mode for this JWE.
		// In this example we are using the direct key management mode, which means
		// the given key will be used directly as the content encryption key.
		senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);

		// Set the "enc" header, which indicates the content encryption algorithm to be
		// used.
		// This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES
		// CBC
		// and HMAC SHA2 that provides authenticated encryption.
		senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

		// Set the key on the JWE. In this case, using direct mode, the key will used
		// directly as
		// the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to
		// encrypt the
		// content requires a 256 bit key.
		senderJwe.setKey(jwk.getKey());

		// Produce the JWE compact serialization, which is where the actual encryption
		// is done.
		// The JWE compact serialization consists of five base64url encoded parts
		// combined with a dot ('.') character in the general format of
		// <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication
		// tag>
		// Direct encryption doesn't use an encrypted key so that field will be an empty
		// string
		// in this case.
		String compactSerialization = null;
		try {
			compactSerialization = senderJwe.getCompactSerialization();
		} catch (JoseException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Compact:" + compactSerialization);
		return compactSerialization;
	}
}
