package in.neuw.mfa.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import in.neuw.mfa.config.props.DuoClientProperties;
import in.neuw.mfa.models.JsonNodeWrapper;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class JWTHelper {

    private final DuoClientProperties duoClientProperties;
    private final ObjectMapper objectMapper;
    private final MACSigner macSigner;
    private final MACVerifier macVerifier;

    public JWTHelper(DuoClientProperties duoClientProperties,
                     final ObjectMapper objectMapper) throws JOSEException {
        this.duoClientProperties = duoClientProperties;
        this.objectMapper = objectMapper;
        this.macSigner = new MACSigner(duoClientProperties.getClientSecret());
        this.macVerifier = new MACVerifier(duoClientProperties.getClientSecret());
    }

    @SneakyThrows
    public String getAuthoriseJWT(final String username) {
        JWSHeader jwsHeader = new JWSHeader
                .Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT signedJWT = new SignedJWT(jwsHeader, getAuthoriseJWTClaimsSet(username));
        signedJWT.sign(macSigner);
        return signedJWT.serialize();
    }

    @SneakyThrows
    public String getAssertionJWT() {
        JWSHeader jwsHeader = new JWSHeader
                .Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .build();
        JWSSigner jwsSigner = new MACSigner(duoClientProperties.getClientSecret());
        SignedJWT signedJWT = new SignedJWT(jwsHeader, getAssertionJWTClaimsSet());
        signedJWT.sign(jwsSigner);
        return signedJWT.serialize();
    }

    public JWTClaimsSet getAuthoriseJWTClaimsSet(final String username) {
        JWTClaimsSet.Builder jwtClaimsBuilder = new JWTClaimsSet.Builder();

        jwtClaimsBuilder
                // mandatory, has to be equal duo client id
                .issuer(duoClientProperties.getClientId())
                // mandatory, has to be equal duo api hostname
                .audience(duoClientProperties.getApiHostName())
                // mandatory, JWT ID
                .jwtID(UUID.randomUUID().toString())
                // mandatory, has to be equal to username
                .subject(username)
                // mandatory, has to be equal to duo client id
                .claim("client_id", duoClientProperties.getClientId())
                // mandatory, has to be equal to code
                .claim("response_type", "code")
                // mandatory, has to be equal to openid
                .claim("scope", "openid")
                // optional
                .claim("state", UUID.randomUUID().toString())
                // optional
                .claim("nonce", UUID.randomUUID().toString())
                // mandatory, has to be equal application callback url
                .claim("redirect_uri", duoClientProperties.getCallbackUrl())
                // mandatory, has to be equal username
                .claim("duo_uname", username)
                // optional, if set, the callback url request param = duo_code
                .claim("use_duo_code_attribute", true)
                // mandatory, expiry of the jwt
                .expirationTime(new Date(System.currentTimeMillis() + (5 * 1000 * 60)))
                // optional, issue date of the jwt
                .issueTime(new Date());

        return jwtClaimsBuilder.build();
    }

    public JWTClaimsSet getAssertionJWTClaimsSet() {
        JWTClaimsSet.Builder jwtClaimsBuilder = new JWTClaimsSet.Builder();

        jwtClaimsBuilder
                .issuer(duoClientProperties.getClientId())
                .audience(duoClientProperties.getApiHostName()+duoClientProperties.getTokenEndpoint())
                .jwtID(UUID.randomUUID().toString())
                .subject(duoClientProperties.getClientId())
                .expirationTime(new Date(System.currentTimeMillis() + (5 * 1000 * 60)))
                .issueTime(new Date());

        return jwtClaimsBuilder.build();
    }

    @SneakyThrows
    public Boolean checkAuthResult(final String token) {
        JsonNodeWrapper jsonNodeWrapper = getClaimIfPresent(token, JsonNodeType.STRING, "auth_result", "result");
        if (jsonNodeWrapper.isPresent()) {
            return jsonNodeWrapper.getNode().asText().equalsIgnoreCase("allow");
        }
        return false;
    }

    @SneakyThrows
    public ArrayList<String> getGroups(final String token) {
        var jsonNodeWrapper = getClaimIfPresent(token, JsonNodeType.ARRAY, "auth_context", "user", "groups");
        if (jsonNodeWrapper.isPresent()) {
            var arrayNode = (ArrayNode) jsonNodeWrapper.getNode();
            var groups = new ArrayList<String>();
            for (var node : arrayNode) {
                if (node.isTextual()) {
                    groups.add(node.asText());
                } // else throw an error etc.
            }
            return groups;
        }
        return new ArrayList<>();
    }

    public boolean checkClaimIfPresent(final String token,
                                       final JsonNodeType nodeType,
                                       final String... claimKeyChain) throws ParseException, JOSEException {
        if (!verifyToken(token)) {
            return false;
        }
        var claims = getClaims(token);
        var claimsNode = getClaimsNode(claims);
        if (claimKeyChain.length > 1) {
            var chainedNode = claimsNode.path(claimKeyChain[0]);
            for (int i = 1; i < claimKeyChain.length ; i++) {
                chainedNode = chainedNode.path(claimKeyChain[i]);
            }
            return !chainedNode.isMissingNode();
        } else {
            return claimsNode.has(claimKeyChain[0]) && claimsNode.getNodeType().equals(nodeType);
        }
    }

    public JsonNodeWrapper getClaimIfPresent(final String token,
                                             final JsonNodeType nodeType,
                                             final String... claimKeyChain) throws ParseException, JOSEException {
        if (!verifyToken(token)) {
            throw new RuntimeException("claim with chain - "+claimKeyChain+" is not present");
        }
        var jsonNodeWrapper = new JsonNodeWrapper();
        var claimsNode = getClaimsNode(getClaims(token));
        if (claimKeyChain.length > 1) {
            var chainedNode = claimsNode.path(claimKeyChain[0]);
            for (int i = 1; i < claimKeyChain.length; i++) {
                chainedNode = chainedNode.path(claimKeyChain[i]);
            }
            jsonNodeWrapper.setNode(chainedNode);
            jsonNodeWrapper.setPresent(!chainedNode.isMissingNode());
        } else {
            jsonNodeWrapper.setPresent(claimsNode.has(claimKeyChain[0]) && claimsNode.getNodeType().equals(nodeType));
            jsonNodeWrapper.setNode(claimsNode.get(claimKeyChain[0]));
        }
        return jsonNodeWrapper;
    }

    private Map<String, Object> getClaims(final String token) throws ParseException {
        return SignedJWT.parse(token).getPayload().toJSONObject();
    }

    private JsonNode getClaimsNode(final Map<String, Object> claimsMap) {
        return objectMapper.valueToTree(claimsMap);
    }

    public boolean verifyToken(final String token) throws ParseException, JOSEException {
        if (SignedJWT.parse(token).verify(macVerifier)) {
            return true;
        }
        return false;
    }

}
