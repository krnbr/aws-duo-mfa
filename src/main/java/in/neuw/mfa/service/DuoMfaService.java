package in.neuw.mfa.service;

import in.neuw.mfa.config.props.DuoClientProperties;
import in.neuw.mfa.models.TokenResponse;
import in.neuw.mfa.utils.JWTHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.ArrayList;

@Service
public class DuoMfaService {

    private final Logger logger = LoggerFactory.getLogger(DuoMfaService.class);

    private final DuoClientProperties duoClientProperties;
    private final JWTHelper jwtHelper;
    private final RestClient duoRestClient;

    public DuoMfaService(final DuoClientProperties duoClientProperties,
                         final JWTHelper jwtHelper,
                         final RestClient duoRestClient) {
        this.duoClientProperties = duoClientProperties;
        this.jwtHelper = jwtHelper;
        this.duoRestClient = duoRestClient;
    }

    public URI initiateMFA(final String username) {
        String authorizeJWT = jwtHelper.getAuthoriseJWT(username);
        return URI.create(duoClientProperties.getApiHostName().concat(authorizeDuoRedirect(authorizeJWT).getHeaders().getLocation().toString()));
    }

    public Boolean validateDuoAuthCode(final String code) {
        String jwt = jwtHelper.getAssertionJWT();
        ResponseEntity<TokenResponse> tokenResponseResponseEntity = getToken(code, jwt);
        if (tokenResponseResponseEntity.getStatusCode().is2xxSuccessful() && tokenResponseResponseEntity.hasBody()) {
            boolean isAllowed = jwtHelper.checkAuthResult(tokenResponseResponseEntity.getBody().getIdToken());
            ArrayList<String> groups = jwtHelper.getGroups(tokenResponseResponseEntity.getBody().getIdToken());
            return isAllowed && groups.contains(duoClientProperties.getAllowedGroupName());
        }
        return false;
    }

    private ResponseEntity<TokenResponse> getToken(final String code,
                                         final String jwt) {
        MultiValueMap<String, String> parts = new LinkedMultiValueMap<>();
        parts.add("client_assertion", jwt);
        parts.add("grant_type", "authorization_code");
        parts.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        parts.add("code", code);
        parts.add("redirect_uri", duoClientProperties.getCallbackUrl());
        parts.add("client_id", duoClientProperties.getClientId());
        return duoRestClient
                .post()
                .uri(duoClientProperties.getTokenEndpoint())
                .body(parts)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .retrieve()
                .toEntity(TokenResponse.class);
    }

    private ResponseEntity<Void> authorizeDuoRedirect(final String jwt) {
        MultiValueMap<String, String> parts = new LinkedMultiValueMap<>();
        parts.add("request", jwt);
        parts.add("response_type","code");
        parts.add("client_id", duoClientProperties.getClientId());
        return duoRestClient
                .post()
                .uri(duoClientProperties.getAuthorizeEndpoint())
                .body(parts)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .retrieve()
                .toBodilessEntity();
    }

}
