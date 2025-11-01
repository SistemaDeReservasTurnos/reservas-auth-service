package com.servicio.reservas.auth.infraestructure.config;

import com.servicio.reservas.auth.infraestructure.users.UserClient;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {
    @Bean
    public UserDetailsService userDetailsService(UserClient userClient) {
        return username -> {
            UserDTO user = userClient.findByEmail(username);

            return User.builder()
                    .username(user.getEmail())
                    .password(user.getPassword())
                    .build();
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
