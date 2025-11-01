package com.servicio.reservas.auth.infraestructure.persistance;

import com.servicio.reservas.auth.domain.entities.Token;
import com.servicio.reservas.auth.domain.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
public class TokenRepositoryPersistance implements TokenRepository {
    private final SpringRepositoryPersistance springRepositoryPersistence;

    @Override
    public void save(Token token) {
        springRepositoryPersistence.save(TokenModelMapper.toModel(token));
    }

    @Override
    public List<Token> findAllByRevokedFalseOrExpiredFalseAndUsername(String username) {
        List<TokenModel> tokens = springRepositoryPersistence.findAllByRevokedFalseOrExpiredFalseAndUsername(username);

        return tokens.stream()
                .map(TokenModelMapper::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public void saveAll(List<Token> tokens) {
        springRepositoryPersistence.saveAll(
                tokens.stream()
                .map(TokenModelMapper::toModel)
                .collect(Collectors.toList())
        );
    }
}
