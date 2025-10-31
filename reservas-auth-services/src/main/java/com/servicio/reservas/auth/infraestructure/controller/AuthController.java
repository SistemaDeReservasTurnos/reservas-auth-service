package com.servicio.reservas.auth.infraestructure.controller;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.dto.TokenResponse;
import com.servicio.reservas.auth.application.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest registerRequest) {
        try {
            TokenResponse tokenResponse = authService.register(registerRequest);

            return ResponseEntity.status(HttpStatus.CREATED).body(tokenResponse);
        } catch (Exception e) {
            System.out.println(e.getMessage());

            return ResponseEntity.badRequest().build();
        }
    }
}
