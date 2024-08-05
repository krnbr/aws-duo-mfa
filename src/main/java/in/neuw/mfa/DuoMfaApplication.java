package in.neuw.mfa;

import in.neuw.mfa.config.props.AWSConfigProperties;
import in.neuw.mfa.config.props.DuoClientProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class, ReactiveUserDetailsServiceAutoConfiguration.class})
@EnableConfigurationProperties({DuoClientProperties.class, AWSConfigProperties.class})
public class DuoMfaApplication {

    public static void main(String[] args) {
        SpringApplication.run(DuoMfaApplication.class, args);
    }

}
