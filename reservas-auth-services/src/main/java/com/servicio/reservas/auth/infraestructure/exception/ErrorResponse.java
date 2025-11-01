package com.servicio.reservas.auth.infraestructure.exception;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class ErrorResponse {
    private LocalDateTime timestamp;
    private int status;
    private String message;
    private String path;
    private Object errors;

    public ErrorResponse(int status, String message, String path, Object errors) {
        this.timestamp = LocalDateTime.now();
        this.status = status;
        this.message = message;
        this.path = path;
        this.errors = errors;
    }
}
