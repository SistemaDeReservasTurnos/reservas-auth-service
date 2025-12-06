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
public class OAuth2LoginIntegrationTest {
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
    }

    /**
     * Test 1: Autenticación Exitosa Password Grant (200 OK con Tokens).
     * <p>
     * Verifica el flujo principal de inicio de sesión (Happy Path).
     * <p>
     * El sistema debe:
     * 1. Recibir credenciales válidas de usuario (email/password) y de cliente (gateway/secret).
     * 2. Autenticar al cliente usando Basic Auth.
     * 3. Autenticar al usuario verificando su existencia y contraseña (mockeado via UserClient).
     * 4. Generar y devolver un par de tokens (Access Token y Refresh Token) válidos.
     */
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
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(899))
                .andExpect(jsonPath("$.userId").value(mockUserDto.getId()))
                .andExpect(jsonPath("$.name").value(mockUserDto.getName()))
                .andExpect(jsonPath("$.email").value(mockUserDto.getEmail()));
    }

    /**
     * Test 2: Autenticación Fallida - Credenciales Incorrectas (400 Invalid Grant).
     * <p>
     * Verifica que el sistema rechace intentos de login con contraseñas erróneas.
     * <p>
     * El sistema debe:
     * 1. Validar las credenciales proporcionadas contra el UserClient.
     * 2. Detectar que la contraseña no coincide.
     * 3. Devolver un error estándar OAuth2 `invalid_grant` con estado 400 Bad Request.
     * 4. No emitir ningún token.
     */
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

    /**
     * Test 3: Refresco de Token Exitoso (200 OK).
     * <p>
     * Verifica el flujo de renovación de sesión mediante `refresh_token`.
     * <p>
     * El sistema debe:
     * 1. Aceptar un `refresh_token` válido emitido previamente.
     * 2. Verificar que el token no haya expirado ni sido revocado en la base de datos.
     * 3. Generar un **nuevo** `access_token`.
     * 4. Generar un **nuevo** `refresh_token` (Rotación de tokens activada).
     * 5. Devolver los nuevos tokens con estado 200 OK.
     */
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
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(899))
                .andExpect(jsonPath("$.refresh_token").value(Matchers.not(refreshToken)));
    }

    /**
     * Test 4: Servicio de Usuarios No Disponible.
     * <p>
     * Verifica la resiliencia y el manejo de errores cuando el microservicio de usuarios downstream falla.
     * <p>
     * El sistema debe:
     * 1. Intentar contactar al UserClient durante el login.
     * 2. Capturar la excepción de conexión (simulada).
     * 3. No "explotar" con un error 500 genérico.
     * 4. Traducir el error interno a un error OAuth2 `temporarily_unavailable`.
     * 5. Devolver este error específico para que el Gateway pueda manejarlo (ej. devolviendo 503).
     */
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

    /**
     * Test 5: Revocación de Token Exitosa.
     * <p>
     * Verifica la capacidad de invalidar tokens bajo demanda (Logout).
     * <p>
     * El sistema debe:
     * 1. Permitir al cliente autenticado llamar al endpoint `/oauth2/revoke`.
     * 2. Marcar el token proporcionado como revocado en la base de datos.
     * 3. Responder con 200 OK.
     * 4. Rechazar cualquier intento posterior de usar ese token para refrescar la sesión,
     * devolviendo `invalid_grant`.
     */
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
