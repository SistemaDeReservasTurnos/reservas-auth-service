package com.servicio.reservas.auth.infraestructure.persistance;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SpringRepositoryPersistance extends JpaRepository<TokenModel, Long> {
}
