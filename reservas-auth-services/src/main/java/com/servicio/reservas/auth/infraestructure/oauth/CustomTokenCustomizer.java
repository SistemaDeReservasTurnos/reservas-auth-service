package com.servicio.reservas.auth.infraestructure.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class CustomTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        JwtClaimsSet.Builder claims = context.getClaims();

        if (principal.getPrincipal() instanceof UserDetails userDetails) {
            claims.claim("name", userDetails.getUsername());
            Set<String> authorities = new HashSet<>();

            for (GrantedAuthority authority : principal.getAuthorities()) {
                authorities.add(authority.getAuthority());
            }

            claims.claim("authorities", authorities);
        }
    }
}
