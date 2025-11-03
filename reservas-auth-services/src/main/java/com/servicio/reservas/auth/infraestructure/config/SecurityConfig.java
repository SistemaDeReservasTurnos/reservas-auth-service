package com.servicio.reservas.auth.infraestructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicio.reservas.auth.application.ports.in.IAuthService;
import com.servicio.reservas.auth.infraestructure.exception.ErrorResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final IAuthService authService;
    private final ObjectMapper objectMapper;
    private final String LOGOUT_ERROR = "logoutError";

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req -> req.requestMatchers("/api/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logout ->
                        logout.logoutUrl("/api/auth/logout")
                                .addLogoutHandler((request, response, authentication) -> {
                                    final var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
                                    try {
                                        authService.logout(authHeader);
                                    } catch (BadCredentialsException e) {
                                        request.setAttribute(LOGOUT_ERROR, true);

                                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                                        ErrorResponse errorBody = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), e.getLocalizedMessage(), request.getRequestURI(), null);

                                        try {
                                            objectMapper.writeValue(response.getWriter(), errorBody);
                                        } catch (Exception ioException) {
                                            log.error("Error serializing error response", ioException);
                                        }
                                    }
                                })
                                .logoutSuccessHandler(((request, response, authentication) -> {
                                    if (request.getAttribute(LOGOUT_ERROR) == null) {
                                        SecurityContextHolder.clearContext();
                                        response.setStatus(HttpStatus.OK.value());
                                    }
                                }))
                );

        return http.build();
    }
}
