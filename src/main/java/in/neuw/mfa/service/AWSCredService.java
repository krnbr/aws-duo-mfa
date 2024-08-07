package in.neuw.mfa.service;

import com.fasterxml.jackson.databind.node.ObjectNode;
import in.neuw.mfa.config.props.AWSConfigProperties;
import in.neuw.mfa.config.props.DuoClientProperties;
import in.neuw.mfa.models.AwsCredentialsResponse;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.GetRoleResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.net.URI;
import java.net.URLEncoder;

@Service
public class AWSCredService {

    private Logger logger = LoggerFactory.getLogger(AWSCredService.class);

    @Autowired
    private DuoMfaService duoMfaService;

    @Autowired
    private AWSConfigProperties awsConfigProperties;

    @Autowired
    private DuoClientProperties duoClientProperties;

    @Autowired
    private IamClient iamClient;

    @Autowired
    private StsClient stsClient;

    @Autowired
    private RestClient awsRestClient;

    @SneakyThrows
    public String getSignInUrl(final String code) {
        // auth code is valid, proceed further with
        if (duoMfaService.validateDuoAuthCode(code)) {
            return getSignInUrlForAssumedRole(awsConfigProperties.getAssumedRoleArn());
        }
        throw new RuntimeException("authentication failure");
    }

    @SneakyThrows
    public String getSignInUrlForAssumedRole(final String roleArn) {
        Credentials credentials = getCredentialsForAssumedRole(roleArn);
        String sessionJson = String.format(
                "{\"%1$s\":\"%2$s\",\"%3$s\":\"%4$s\",\"%5$s\":\"%6$s\"}",
                "sessionId", credentials.accessKeyId(),
                "sessionKey", credentials.secretAccessKey(),
                "sessionToken", credentials.sessionToken());
        String getSigninTokenURL = awsConfigProperties.getSignInUrl() +
                "?Action=getSigninToken" +
                "&DurationSeconds=" + awsConfigProperties.getSessionDuration() +
                "&SessionType=json&Session=" +
                URLEncoder.encode(sessionJson,"UTF-8");

        ResponseEntity<ObjectNode> objectNodeResponseEntity = awsRestClient.get()
                .uri(new URI(getSigninTokenURL))
                // this was not needed
                //.header(HttpHeaders.ACCEPT, APPLICATION_JSON_VALUE)
                .retrieve().toEntity(ObjectNode.class);

        String signinToken;
        if (objectNodeResponseEntity.getStatusCode().is2xxSuccessful() && objectNodeResponseEntity.hasBody()) {

            signinToken = objectNodeResponseEntity.getBody().get("SigninToken").asText();
        } else {
            throw new RuntimeException("could not resolve the signIn token");
        }

        String signinTokenParameter = "&SigninToken=" + URLEncoder.encode(signinToken,"UTF-8");

        String destinationParameter = "&Destination=" + URLEncoder.encode(awsConfigProperties.getConsoleUrl(),"UTF-8");
        String loginURL = awsConfigProperties.getSignInUrl() + "?Action=login" +
                signinTokenParameter + destinationParameter;

        return loginURL;
    }

    public Credentials getCredentialsForAssumedRole(final String roleArn) {
        return getResponse(roleArn).credentials();
    }

    public AwsCredentialsResponse getAwsCredentials(final String roleArn) {
        Credentials credentials = getResponse(roleArn).credentials();
        AwsCredentialsResponse response = new AwsCredentialsResponse();
        response.setAccessKeyId(credentials.accessKeyId());
        response.setSecretAccessKey(credentials.secretAccessKey());
        response.setExpiration(credentials.expiration());
        return response;
    }

    private AssumeRoleResponse getResponse(final String roleArn) {
        AssumeRoleResponse response = stsClient.assumeRole(request(roleArn));
        return response;
    }

    private AssumeRoleRequest request(final String roleArn) {

        // this is redundant as we are going to fetch the role using the get role API
        // & will use the duration from there only
        int duration = awsConfigProperties.getSessionDuration();

        if(roleArn.startsWith("arn:aws:iam::")) {
            String roleName = roleArn.split("/")[1];
            GetRoleResponse response = getRole(roleName);
            duration = response.role().maxSessionDuration();
            logger.info("duration for the assumed role - {} is {} seconds", roleName, duration);
        }

        //GetFederationTokenRequest.builder().
        //stsClient.getFederationToken(GetFederationTokenRequest)

        return AssumeRoleRequest.builder().roleArn(roleArn)
                .roleSessionName(duoClientProperties.getUsername())
                .durationSeconds(duration).build();
    }

    private GetRoleResponse getRole(final String roleArn) {
        GetRoleRequest request = GetRoleRequest.builder()
                .roleName(roleArn)
                .build();
        return iamClient.getRole(request);
    }

}
