package com.servicio.reservas.auth.infraestructure.config;

import com.servicio.reservas.auth.application.exception.ServiceUnavailableException;
import com.servicio.reservas.auth.domain.entities.Role;
import com.servicio.reservas.auth.infraestructure.users.UserClient;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {
    @Bean
    public UserDetailsService userDetailsService(UserClient userClient) {
        return username -> {
            try {
                UserDTO user = userClient.findByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                Role role = Role.fromString(user.getRole());

                return User.builder()
                        .username(user.getEmail())
                        .password(user.getPassword())
                        .roles(role.toString())
                        .build();
            } catch (ServiceUnavailableException e) {
                throw new AuthenticationServiceException("Service Unavailable. Try again later.");
            }
        };
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
