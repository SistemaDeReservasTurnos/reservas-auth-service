package com.servicio.reservas.auth.domain.entities;

public enum Role {
    CLIENTE,
    EMPLEADO,
    ADMINISTRADOR;

    public static Role fromString(String text) {
        if (text == null) {
            throw new IllegalArgumentException("Role cannot be null. Valid roles are: CLIENTE, EMPLEADO, ADMINISTRADOR.");
        }

        try {
            String cleanedText = text.trim().toUpperCase();

            return Role.valueOf(cleanedText);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + text + ". Valid roles are: CLIENTE, EMPLEADO, ADMINISTRADOR.");
        }
    }

    public static void validate(String text) {
        if (text == null) {
            throw new IllegalArgumentException("Role cannot be null. Valid roles are: CLIENTE, EMPLEADO, ADMINISTRADOR.");
        }

        try {
            String cleanedText = text.trim().toUpperCase();

            Role.valueOf(cleanedText);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + text + ". Valid roles are: CLIENTE, EMPLEADO, ADMINISTRADOR.");
        }
    }
}
