package com.servicio.reservas.auth.application.ports.in;

import com.servicio.reservas.auth.infraestructure.users.UserDTO;

public interface ITokenService {
    String generateToken(UserDTO user);
    String generateRefreshToken(UserDTO user);
}
