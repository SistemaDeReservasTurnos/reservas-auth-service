package com.servicio.reservas.auth.domain.entities;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Token {
    private int id;
    private String token;
    private boolean revoked;
    private boolean expired;
    private String username;
}
