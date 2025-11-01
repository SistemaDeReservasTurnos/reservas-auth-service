package com.servicio.reservas.auth.infraestructure.users;

import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserClientConfig {
    @Bean
    public ErrorDecoder errorDecoder() {
        return new MyCustomErrorDecoder();
    }
}
