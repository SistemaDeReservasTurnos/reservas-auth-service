package com.servicio.reservas.auth.infraestructure.exceptions;

import com.servicio.reservas.auth.application.exceptions.ServiceUnavailableException;
import com.servicio.reservas.auth.application.exceptions.UserAlreadyExistException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleValidationException(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            if (error instanceof FieldError) {
                String fieldName = ((FieldError) error).getField();
                String errorMessage = error.getDefaultMessage();
                fieldErrors.put(fieldName, errorMessage);
            }
        });

        return new ErrorResponse(HttpStatus.BAD_REQUEST.value(), "Bad Request", request.getRequestURI(), fieldErrors);
    }

    @ExceptionHandler(UserAlreadyExistException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse handleUserAlreadyExistException(UserAlreadyExistException ex, HttpServletRequest request) {
        return new ErrorResponse(HttpStatus.CONFLICT.value(), ex.getLocalizedMessage(), request.getRequestURI(), null);
    }

    @ExceptionHandler({AuthenticationServiceException.class, ServiceUnavailableException.class})
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorResponse handleAuthenticationServiceException(Exception ex, HttpServletRequest request) {
        return new ErrorResponse(HttpStatus.SERVICE_UNAVAILABLE.value(), ex.getLocalizedMessage(), request.getRequestURI(), null);
    }
}
