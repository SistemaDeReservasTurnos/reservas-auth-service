package com.servicio.reservas.auth.domain.repository;

import com.servicio.reservas.auth.domain.entities.Token;

public interface TokenRepository {
    Token save(Token token);
}
