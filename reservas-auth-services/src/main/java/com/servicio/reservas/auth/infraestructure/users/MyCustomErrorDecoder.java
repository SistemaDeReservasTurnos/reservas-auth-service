package com.servicio.reservas.auth.infraestructure.users;

import feign.Response;
import feign.codec.ErrorDecoder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyCustomErrorDecoder implements ErrorDecoder {
    private final ErrorDecoder defaultDecoder = new ErrorDecoder.Default();

    @Override
    public Exception decode(String methodKey, Response response) {
        if (response.status() == 404 && methodKey.contains("findByEmail")) {
            return new UsernameNotFoundException("User not found");
        }

        return defaultDecoder.decode(methodKey, response);
    }
}
