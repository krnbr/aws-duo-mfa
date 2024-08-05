package in.neuw.mfa.config;

import in.neuw.mfa.config.props.DuoClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class DuoMfaConfig {

    private final DuoClientProperties duoClientProperties;

    public DuoMfaConfig(DuoClientProperties duoClientProperties) {
        this.duoClientProperties = duoClientProperties;
    }

    @Bean
    public RestClient duoRestClient(final RestClient.Builder restClientBuilder) {
        return restClientBuilder.baseUrl(duoClientProperties.getApiHostName()).build();
    }

}
