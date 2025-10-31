package com.servicio.reservas.auth.application.dto;

import lombok.Data;

@Data
public class UserDTO {
    private Long id;
    private String name;
    private String email;
    private String password;
    private String phone_number;
    private String role;
}
