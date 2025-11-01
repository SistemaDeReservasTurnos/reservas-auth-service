package com.servicio.reservas.auth.application.services;

import com.servicio.reservas.auth.application.dto.LoginRequest;
import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.dto.TokenResponse;
import com.servicio.reservas.auth.application.ports.in.IAuthService;
import com.servicio.reservas.auth.application.ports.in.ITokenService;
import com.servicio.reservas.auth.domain.entities.Role;
import com.servicio.reservas.auth.domain.entities.Token;
import com.servicio.reservas.auth.domain.repository.TokenRepository;
import com.servicio.reservas.auth.infraestructure.users.UserClient;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserClient userClient;
    private final TokenRepository tokenRepository;
    private final ITokenService tokenService;
    private final AuthenticationManager authenticationManager;

    @Override
    public TokenResponse register(RegisterRequest registerRequest) {
        registerRequest.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        Role.fromString(registerRequest.getRole());
        UserDTO user = userClient.create(registerRequest);

        String jwtToken = tokenService.generateToken(user);
        String jwtRefreshToken = tokenService.generateRefreshToken(user);
        saveUserToken(user, jwtToken);

        return new TokenResponse(jwtToken, jwtRefreshToken);
    }

    @Override
    public TokenResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        UserDTO user = userClient.findByEmail(loginRequest.getEmail());
        String jwtToken = tokenService.generateToken(user);
        String jwtRefreshToken = tokenService.generateRefreshToken(user);

        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        return new TokenResponse(jwtToken, jwtRefreshToken);
    }

    private void revokeAllUserTokens(UserDTO user) {
        List<Token> validUserTokens = tokenRepository.findAllByRevokedFalseOrExpiredFalseAndUsername(user.getEmail());

        if (!validUserTokens.isEmpty()) {
            for (final Token token : validUserTokens) {
                token.setRevoked(true);
                token.setExpired(true);
            }
            tokenRepository.saveAll(validUserTokens);
        }
    }

    private void saveUserToken(UserDTO user, String jwtToken) {
        Token token = Token.builder().token(jwtToken).revoked(false).expired(false).username(user.getEmail()).build();
        tokenRepository.save(token);
    }
}
