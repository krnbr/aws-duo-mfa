package in.neuw.mfa.config.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "duo")
public class DuoClientProperties {

    private String callbackUrl;
    private String clientId;
    private String clientSecret;
    private String apiHostName;
    private String authorizeEndpoint;
    private String tokenEndpoint;
    private String username;
    private String allowedGroupName;

}
