package in.neuw.mfa.config;

import in.neuw.mfa.config.props.AWSConfigProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.StsClient;

@Configuration
public class AWSConfig {

    @Bean
    public AwsCredentials awsCredentials(final AWSConfigProperties awsConfigProperties) {
        AwsCredentials creds = AwsBasicCredentials.create(awsConfigProperties.getAccessKeyId(), awsConfigProperties.getSecretAccessKey());
        return creds;
    }

    @Bean
    public AwsCredentialsProvider awsCredentialsProvider(final AwsCredentials awsCredentials) {
        return StaticCredentialsProvider.create(awsCredentials);
    }

    @Bean
    public StsClient stsClient(final AwsCredentialsProvider awsCredentialsProvider,
                               final AWSConfigProperties awsConfigProperties) {
        StsClient client = StsClient.builder()
                .region(Region.of(awsConfigProperties.getDefaultRegion()))
                .credentialsProvider(awsCredentialsProvider)
                .build();
        return client;
    }

    @Bean
    public IamClient iamClient(final AwsCredentialsProvider awsCredentialsProvider) {
        IamClient iamClient = IamClient.builder()
                .region(Region.AWS_GLOBAL)
                .credentialsProvider(awsCredentialsProvider)
                .build();
        return iamClient;
    }

    @Bean
    public RestClient awsRestClient(RestClient.Builder builder) {
        return builder.build();
    }

}
