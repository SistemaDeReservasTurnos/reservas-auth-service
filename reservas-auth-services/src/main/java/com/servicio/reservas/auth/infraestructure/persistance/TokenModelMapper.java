package com.servicio.reservas.auth.infraestructure.persistance;

import com.servicio.reservas.auth.domain.entities.Token;

public class TokenModelMapper {
    public static TokenModel toModel(Token token) {
        return TokenModel.builder()
                .id(token.getId())
                .token(token.getToken())
                .revoked(token.isRevoked())
                .expired(token.isExpired())
                .username(token.getUsername())
                .build();
    }

    public static Token toEntity(TokenModel tokenModel) {
        return Token.builder()
                .id(tokenModel.getId())
                .token(tokenModel.getToken())
                .revoked(tokenModel.isRevoked())
                .expired(tokenModel.isExpired())
                .username(tokenModel.getUsername())
                .build();
    }
}
