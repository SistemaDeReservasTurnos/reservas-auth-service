package com.servicio.reservas.auth.application.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
    private String phone_number;
    private String role;
}
