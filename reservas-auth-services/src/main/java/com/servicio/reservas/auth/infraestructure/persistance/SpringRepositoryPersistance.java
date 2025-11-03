package com.servicio.reservas.auth.infraestructure.persistance;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SpringRepositoryPersistance extends JpaRepository<TokenModel, Long> {
    @Query("SELECT t FROM TokenModel t WHERE t.username = :username AND (t.revoked = false OR t.expired = false)")
    List<TokenModel> findAllByRevokedFalseOrExpiredFalseAndUsername(@Param("username") String username);
    TokenModel findByToken(String token);
}
