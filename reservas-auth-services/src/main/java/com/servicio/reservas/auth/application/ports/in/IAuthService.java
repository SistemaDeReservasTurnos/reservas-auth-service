package com.servicio.reservas.auth.application.ports.in;

import com.servicio.reservas.auth.application.dto.LoginRequest;
import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.dto.TokenResponse;

public interface IAuthService {
    TokenResponse register(RegisterRequest registerRequest);
    TokenResponse login(LoginRequest loginRequest);
    TokenResponse refreshToken(String authHeader);
    void logout(String authHeader);
}
