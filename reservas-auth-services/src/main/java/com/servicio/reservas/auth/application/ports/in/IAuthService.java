package com.servicio.reservas.auth.application.ports.in;

import com.servicio.reservas.auth.application.dto.RegisterRequest;

public interface IAuthService {
    void register(RegisterRequest registerRequest);
}
