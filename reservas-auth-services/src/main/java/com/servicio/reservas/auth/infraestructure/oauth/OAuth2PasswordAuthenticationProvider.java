package com.servicio.reservas.auth.infraestructure.oauth;

import com.servicio.reservas.auth.infraestructure.config.CustomUserDetails;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;


    public OAuth2PasswordAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder, OAuth2AuthorizationService authorizationService, OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken passwordGrantAuthenticationToken = (OAuth2PasswordAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(passwordGrantAuthenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(passwordGrantAuthenticationToken.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Set<String> authorizedScopes = getAuthorizedScopes(passwordGrantAuthenticationToken, registeredClient);

        String providedUsername = passwordGrantAuthenticationToken.getUsername();
        String providedPassword = passwordGrantAuthenticationToken.getPassword();

        UserDetails userDetails;

        try {
            userDetails = this.userDetailsService.loadUserByUsername(providedUsername);

            if (!this.passwordEncoder.matches(providedPassword, userDetails.getPassword())) {
                throw new BadCredentialsException("Invalid resource owner credentials");
            }
        } catch (UsernameNotFoundException | BadCredentialsException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "Invalid resource owner credentials", null));
        } catch (AuthenticationServiceException ex) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE, ex.getMessage(), null)
            );
        }

        var userPrincipal = new UsernamePasswordAuthenticationToken(userDetails, providedPassword, userDetails.getAuthorities());

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(userPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(passwordGrantAuthenticationToken)
                .put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()))
                .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", null);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());

        OAuth2RefreshToken refreshToken = null;

        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = DefaultOAuth2TokenContext.builder()
                    .registeredClient(registeredClient)
                    .principal(userPrincipal)
                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .authorizedScopes(authorizedScopes)
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .authorizationGrant(passwordGrantAuthenticationToken)
                    .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(refreshTokenContext);

            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", null);
                throw new OAuth2AuthenticationException(error);
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
        }

        Map<String, Object> tokenMetadata = new HashMap<>();
        tokenMetadata.put("username", userDetails.getUsername());
        tokenMetadata.put("roles", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));

        if (!authorizedScopes.isEmpty()) {
            tokenMetadata.put("scopes", authorizedScopes);
        }

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userDetails.getUsername())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .attribute(Principal.class.getName(), userPrincipal)
                .token(accessToken, (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, tokenMetadata));

        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        Map<String, Object> additionalParameters = new HashMap<>();

        if (userDetails instanceof CustomUserDetails customUser) {
            additionalParameters.put("userId", customUser.getId());
            additionalParameters.put("name", customUser.getName());
            additionalParameters.put("email", customUser.getEmail());
            additionalParameters.put("role", customUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
    }

    private static Set<String> getAuthorizedScopes(OAuth2PasswordAuthenticationToken passwordGrantAuthenticationToken, RegisteredClient registeredClient) {
        Set<String> authorizedScopes = Collections.emptySet();

        if (passwordGrantAuthenticationToken.getScopes() != null) {
            for (String requestedScope : passwordGrantAuthenticationToken.getScopes()) {
                if (!registeredClient.getScopes().contains(requestedScope)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }
            }
            authorizedScopes = new LinkedHashSet<>(passwordGrantAuthenticationToken.getScopes());
        }

        return authorizedScopes;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
