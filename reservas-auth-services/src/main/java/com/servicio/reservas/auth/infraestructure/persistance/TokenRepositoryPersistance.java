package com.servicio.reservas.auth.infraestructure.persistance;

import com.servicio.reservas.auth.domain.entities.Token;
import com.servicio.reservas.auth.domain.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class TokenRepositoryPersistance implements TokenRepository {
    private final SpringRepositoryPersistance springRepositoryPersistence;

    @Override
    public Token save(Token token) {
        return TokenModelMapper.toEntity(springRepositoryPersistence.save(TokenModelMapper.toModel(token)));
    }
}
