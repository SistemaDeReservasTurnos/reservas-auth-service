package com.servicio.reservas.auth.application.services;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.ports.in.IAuthService;
import com.servicio.reservas.auth.domain.entities.Role;
import com.servicio.reservas.auth.infraestructure.users.UserClient;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {
    private final UserClient userClient;

    @Override
    public void register(RegisterRequest registerRequest) {
        registerRequest.setRole(Role.CLIENTE.toString());
        System.out.println(registerRequest);
        userClient.create(registerRequest);
    }
}
