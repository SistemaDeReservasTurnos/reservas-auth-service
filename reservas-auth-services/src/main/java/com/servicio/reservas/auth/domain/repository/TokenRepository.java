package com.servicio.reservas.auth.domain.repository;

import com.servicio.reservas.auth.domain.entities.Token;

import java.util.List;

public interface TokenRepository {
    void save(Token token);
    List<Token> findAllByRevokedFalseOrExpiredFalseAndUsername(String username);
    void saveAll(List<Token> tokens);
}
