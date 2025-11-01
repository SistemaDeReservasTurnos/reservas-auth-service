package com.servicio.reservas.auth.infraestructure.persistance;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@Entity
@Table(name = "token")
@NoArgsConstructor
@AllArgsConstructor
public class TokenModel {
    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String token;

    private boolean revoked;

    private boolean expired;

    @Column(nullable = false)
    private String username;
}
