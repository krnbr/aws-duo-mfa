package in.neuw.mfa.models;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class AwsCredentialsResponse {

    private String accessKeyId;
    private String secretAccessKey;
    private Instant expiration;

}