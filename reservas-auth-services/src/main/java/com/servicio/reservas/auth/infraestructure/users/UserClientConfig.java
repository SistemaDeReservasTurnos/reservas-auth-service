package com.servicio.reservas.auth.infraestructure.users;

import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;

public class UserClientConfig {
    @Bean
    public ErrorDecoder errorDecoder() {
        return new MyCustomErrorDecoder();
    }
}
