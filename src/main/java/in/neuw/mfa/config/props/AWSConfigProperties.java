package in.neuw.mfa.config.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "aws")
public class AWSConfigProperties {

    private String accessKeyId;
    private String secretAccessKey;
    private String consoleUrl;
    private String signInUrl;
    private String defaultRegion;
    private Integer sessionDuration;
    private String assumedRoleArn;

}
