package com.servicio.reservas.auth.application.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenResponse {
    private String access_token;
    private String refresh_token;
}
