package com.demo;

import java.security.PublicKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class ZuulRedirectFilter extends ZuulFilter {
	@Value("${Authorities}")
	String Authorities;

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 1;
	}

	@Override
	public boolean shouldFilter() {
		return true;

	}

	@Override
	public Object run() {

		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();

		// if request is to public service
		String[] urlParts = request.getServletPath().split("/");
		System.out.println("**************************URLParts:" + request.getServletPath());
		String serviceUrl = urlParts[1];
		System.out.println("************************Service Url:" + serviceUrl);

		JSONParser parser = new JSONParser();
		JSONObject json = null;
		try {
			json = (JSONObject) parser.parse(Authorities);
		} catch (ParseException e3) {
			return HttpServletResponse.SC_FORBIDDEN;
			// e3.printStackTrace();
		}
		String services = (String) json.get("User");
		String[] servicess = services.split(",");
		System.out.println("*****************Services:" + services);
		for (String service : servicess) {
			if (serviceUrl.equals(service)) {
				// then let go
				return HttpServletResponse.SC_OK;
			}
		}

		// else check if private service request token validation

		// get token from header
		String token = request.getHeader("application-token");
		System.out.println("**************Token:" + token);
		if (token == null) {
			return HttpServletResponse.SC_FORBIDDEN;
		} else {

			// decrypt to verify admin token
			String jwe = token;
			String jwt = null;
			// RsaJsonWebKey rsaJsonWebKey = null;
			PublicKey publicKey = null;

			// That other party, the receiver, can then use JsonWebEncryption to decrypt the
			// message.
			JsonWebEncryption receiverJwe = new JsonWebEncryption();

			// Set the algorithm constraints based on what is agreed upon or expected from
			// the sender
			AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					KeyManagementAlgorithmIdentifiers.DIRECT);
			receiverJwe.setAlgorithmConstraints(algConstraints);
			AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
					ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
			receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

			// Set the compact serialization on new Json Web Encryption object
			try {
				receiverJwe.setCompactSerialization(jwe);
			} catch (JoseException e2) {
				return HttpServletResponse.SC_FORBIDDEN;
				// e2.printStackTrace();
			}

			// The shared secret or shared symmetric key represented as a octet sequence
			// JSON Web Key (JWK)
			String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
			JsonWebKey jwk = null;
			try {
				jwk = JsonWebKey.Factory.newJwk(jwkJson);
			} catch (JoseException e2) {
				return HttpServletResponse.SC_FORBIDDEN;
				// e2.printStackTrace();
			}

			// Symmetric encryption, like we are doing here, requires that both parties have
			// the same key.
			// The key will have had to have been securely exchanged out-of-band somehow.
			receiverJwe.setKey(jwk.getKey());
			// Get the message that was encrypted in the JWE. This step performs the actual
			// decryption steps.
			String plaintext = null;
			try {
				plaintext = receiverJwe.getPlaintextString();
			} catch (JoseException e2) {
				return HttpServletResponse.SC_FORBIDDEN;
				// e2.printStackTrace();
			}

			try {
				if (!(plaintext.equals(" "))) {
					String pkey = plaintext.substring(0, plaintext.indexOf("JWT:") - 1);
					PublicJsonWebKey parsedPublicKeyJwk = null;
					try {
						parsedPublicKeyJwk = PublicJsonWebKey.Factory.newPublicJwk(pkey);
					} catch (JoseException e2) {
						e2.printStackTrace();
					}
					publicKey = parsedPublicKeyJwk.getPublicKey();
					jwt = plaintext.substring(plaintext.indexOf("JWT:") + 4, plaintext.length());
				}

				// Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
				// be used to validate and process the JWT.
				// The specific validation requirements for a JWT are context dependent,
				// however,
				// it typically advisable to require a (reasonable) expiration time, a trusted
				// issuer, and
				// and audience that identifies your system as the intended recipient.
				// If the JWT is encrypted too, you need only provide a decryption key or
				// decryption key resolver to the builder.
				JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime() // the JWT must have an
																								// expiration time
						.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to
															// account
															// for clock skew
						.setRequireSubject() // the JWT must have a subject claim
						.setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
						.setExpectedAudience("Audience") // to whom the JWT is intended for
						.setVerificationKey(publicKey) // verify the signature with the public key
						.setJweAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given
														// context
								new AlgorithmConstraints(ConstraintType.WHITELIST, // which is only RS256 here
										AlgorithmIdentifiers.RSA_USING_SHA256))
						.build(); // create the JwtConsumer instance
				try {
					// Validate the JWT and process it to the Claims
					JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
					System.out.println("JWT validation succeeded! " + jwtClaims);
					// ******************************************************************************************************
					String roles = (String) json.get("roles");
					String[] roless = roles.split(",");
					System.out.println("***********rOLEs" + json.get("roles"));
					for (String role : roless) {
						if (jwtClaims.getSubject().equals(role)) {
							System.out.println("Role Matched...getting services");
							services = (String) json.get(role);
							servicess = services.split(",");
							System.out.println("*****************Services:" + services);
							for (String service : servicess) {
								System.out.println("*************" + service);
								if (service.equals(serviceUrl)) {
									System.out.println("ok");
									return HttpServletResponse.SC_ACCEPTED;
								} else {
									System.out.println("gaandu");
									return HttpServletResponse.SC_FORBIDDEN;
								}
							}
						} else {
							return HttpServletResponse.SC_FORBIDDEN;
						}
					}
					// ******************************************************************************************************
					if (jwtClaims.getSubject().equals("Admin")) {
						return HttpServletResponse.SC_ACCEPTED;
					} else {
						// return login failed
						return HttpServletResponse.SC_FORBIDDEN;
					}
				} catch (InvalidJwtException e) {
					// InvalidJwtException will be thrown, if the JWT failed processing or
					// validation in anyway.
					// Hopefully with meaningful explanations(s) about what went wrong.
					System.out.println("Invalid JWT! " + e);

					// Programmatic access to (some) specific reasons for JWT invalidity is also
					// possible
					// should you want different error handling behavior for certain conditions.

					// Whether or not the JWT has expired being one common reason for invalidity
					if (e.hasExpired()) {
						try {
							System.out
									.println("JWT expired at " + e.getJwtContext().getJwtClaims().getExpirationTime());
						} catch (MalformedClaimException e1) {
							return HttpServletResponse.SC_REQUEST_TIMEOUT;
							// e1.printStackTrace();
						}
					}

					// Or maybe the audience was invalid
					if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
						try {
							System.out.println(
									"JWT had wrong audience: " + e.getJwtContext().getJwtClaims().getAudience());
							return HttpServletResponse.SC_FORBIDDEN;
						} catch (MalformedClaimException e1) {
							return HttpServletResponse.SC_FORBIDDEN;
							// e1.printStackTrace();
						}
					}
					throw new Exception("UnAuthorized");
				}
			} catch (Exception e) {
				return HttpServletResponse.SC_FORBIDDEN;
			}
		}
	}
}