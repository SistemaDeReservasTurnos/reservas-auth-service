package com.servicio.reservas.auth.application.ports.in;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.dto.TokenResponse;

public interface IAuthService {
    TokenResponse register(RegisterRequest registerRequest);
}
