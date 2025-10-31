package com.servicio.reservas.auth.infraestructure.controller;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.dto.TokenResponse;
import com.servicio.reservas.auth.application.ports.in.IAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final IAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@RequestBody RegisterRequest registerRequest) {
        try {
            TokenResponse tokenResponse = authService.register(registerRequest);

            return ResponseEntity.status(HttpStatus.CREATED).body(tokenResponse);
        } catch (Exception e) {

            return ResponseEntity.badRequest().build();
        }
    }
}
