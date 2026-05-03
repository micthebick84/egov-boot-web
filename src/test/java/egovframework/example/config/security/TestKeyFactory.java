package egovframework.example.config.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class TestKeyFactory {

    private static final RSAKey RSA_KEY = generate();

    private static RSAKey generate() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAKey rsaKey() {
        return RSA_KEY;
    }

    public static String signAccessToken(String subject,
                                         String issuer,
                                         List<String> authorities,
                                         Instant expiresAt) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(issuer)
                    .audience("egov-app")
                    .issueTime(java.util.Date.from(Instant.now().minusSeconds(5)))
                    .expirationTime(java.util.Date.from(expiresAt))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("username", subject)
                    .claim("email", subject + "@example.com")
                    .claim("authorities", authorities)
                    .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(RSA_KEY.getKeyID())
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(RSA_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String signIdToken(String subject, String issuer, Instant expiresAt) {
        return signAccessToken(subject, issuer, List.of("ROLE_USER"), expiresAt);
    }
}
