package com.servicio.reservas.auth.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicio.reservas.auth.TestSecurityConfig;
import com.servicio.reservas.auth.application.exceptions.ServiceUnavailableException;
import com.servicio.reservas.auth.domain.entities.Role;
import com.servicio.reservas.auth.infraestructure.users.UserClient;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import java.util.Optional;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
/*
  Integration tests for OAuth2 login endpoints.
  Tests the /oauth2/token endpoint for password grant, refresh token, and revocation flows.
  Uses H2 in-memory database and mocks UserClient for isolation.
  Runs with the 'test' Spring profile.
 */
class OAuth2LoginIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private UserClient userClient;

    @Value("${application.security.client-secret-key}")
    private String clientSecret;

    private UserDTO mockUserDto;

    @BeforeEach
    void setUp() {
        mockUserDto = new UserDTO();
        mockUserDto.setId(1L);
        mockUserDto.setEmail("juan@test.com");
        mockUserDto.setPassword(passwordEncoder.encode("password123"));
        mockUserDto.setRole(Role.CLIENTE.toString());
        mockUserDto.setName("Juan Perez");

        System.out.println(clientSecret);
    }

    @Test
    @DisplayName("Test 1: Autenticación Exitosa Password Grant (200 OK con Tokens)")
    void testLoginSuccess() throws Exception {
        when(userClient.findByEmail("juan@test.com")).thenReturn(Optional.of(mockUserDto));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "juan@test.com");
        params.add("password", "password123");
        params.add("scope", "openid read write");

        mockMvc.perform(post("/oauth2/token")
                        .params(params)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    @DisplayName("Test 2: Autenticación Fallida - Credenciales Incorrectas (400 Invalid Grant)")
    void testLoginBadCredentials() throws Exception {
        when(userClient.findByEmail("juan@test.com")).thenReturn(Optional.of(mockUserDto));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "juan@test.com");
        params.add("password", "WRONG_PASSWORD");

        mockMvc.perform(post("/oauth2/token")
                        .params(params)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    @DisplayName("Test 3: Refresco de Token Exitoso (200 OK)")
    void testRefreshTokenSuccess() throws Exception {
        when(userClient.findByEmail("juan@test.com")).thenReturn(Optional.of(mockUserDto));

        MultiValueMap<String, String> loginParams = new LinkedMultiValueMap<>();
        loginParams.add("grant_type", "password");
        loginParams.add("username", "juan@test.com");
        loginParams.add("password", "password123");

        String responseJson = mockMvc.perform(post("/oauth2/token")
                        .params(loginParams)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String refreshToken = objectMapper.readTree(responseJson).get("refresh_token").asText();

        MultiValueMap<String, String> refreshParams = new LinkedMultiValueMap<>();
        refreshParams.add("grant_type", "refresh_token");
        refreshParams.add("refresh_token", refreshToken);

        mockMvc.perform(post("/oauth2/token")
                        .params(refreshParams)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").value(Matchers.not(refreshToken)));
    }

    @Test
    @DisplayName("Test 4: Servicio de Usuarios No Disponible")
    void testLoginServiceUnavailable() throws Exception {
        when(userClient.findByEmail(anyString()))
                .thenThrow(new ServiceUnavailableException("Service Down"));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("username", "juan@test.com");
        params.add("password", "password123");

        mockMvc.perform(post("/oauth2/token")
                        .params(params)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("temporarily_unavailable"));
    }

    @Test
    @DisplayName("Test 5: Revocación de Token Exitosa")
    void testTokenRevocation() throws Exception {
        // 1. Pre-requisito: Obtener un Refresh Token válido
        when(userClient.findByEmail("juan@test.com")).thenReturn(Optional.of(mockUserDto));

        MultiValueMap<String, String> loginParams = new LinkedMultiValueMap<>();
        loginParams.add("grant_type", "password");
        loginParams.add("username", "juan@test.com");
        loginParams.add("password", "password123");

        String loginResponse = mockMvc.perform(post("/oauth2/token")
                        .params(loginParams)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String refreshToken = objectMapper.readTree(loginResponse).get("refresh_token").asText();

        // 2. Ejecutar Revocación (POST /oauth2/revoke)
        MultiValueMap<String, String> revokeParams = new LinkedMultiValueMap<>();
        revokeParams.add("token", refreshToken);
        revokeParams.add("token_type_hint", "refresh_token");

        mockMvc.perform(post("/oauth2/revoke")
                        .params(revokeParams)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isOk());

        // 3. Verificación: Intentar usar el token revocado para hacer refresh
        MultiValueMap<String, String> refreshParams = new LinkedMultiValueMap<>();
        refreshParams.add("grant_type", "refresh_token");
        refreshParams.add("refresh_token", refreshToken);

        mockMvc.perform(post("/oauth2/token")
                        .params(refreshParams)
                        .with(httpBasic("gateway", clientSecret)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}
