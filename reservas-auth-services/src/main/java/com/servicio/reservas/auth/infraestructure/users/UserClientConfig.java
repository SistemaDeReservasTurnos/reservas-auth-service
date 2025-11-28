package com.servicio.reservas.auth.infraestructure.users;

import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.Objects;

@Configuration
public class UserClientConfig {
    @Bean
    public ErrorDecoder errorDecoder() {
        return new MyCustomErrorDecoder();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    public RequestInterceptor oauth2FeignRequestInterceptor(OAuth2AuthorizedClientManager authorizedClientManager) {
        return requestTemplate -> {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                    .withClientRegistrationId("user-service-client")
                    .principal("reservas-auth-service")
                    .build();

            String accessToken = Objects.requireNonNull(
                    authorizedClientManager.authorize(authorizeRequest),
                            "Failed to obtain OAuth2 access token for user-service-client")
                    .getAccessToken()
                    .getTokenValue();

            requestTemplate.header("Authorization", "Bearer " + accessToken);
        };
    }
}
