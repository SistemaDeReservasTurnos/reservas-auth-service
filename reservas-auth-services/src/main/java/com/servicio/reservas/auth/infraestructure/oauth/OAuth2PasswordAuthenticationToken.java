package com.servicio.reservas.auth.infraestructure.oauth;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import java.util.Set;

@Getter
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;
    private final String clientId;
    private final Set<String> scopes;

    public OAuth2PasswordAuthenticationToken(String username, String password, Authentication clientPrincipal, Set<String> scopes) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, null);
        this.username = username;
        this.password = password;
        this.clientId = clientPrincipal.getName();
        this.scopes = scopes;
    }
}
