package com.servicio.reservas.auth.domain.entities;

public enum Role {
    CLIENTE,
    EMPLEADO,
    ADMINISTRADOR;

    public static Role fromString(String text) {
        if (text == null) {
            return null;
        }

        try {
            String cleanedText = text.trim().toUpperCase();

            return Role.valueOf(cleanedText);

        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + text + ". Valid roles are: CLIENTE, EMPLEADO, ADMINISTRADOR.");
        }
    }
}
