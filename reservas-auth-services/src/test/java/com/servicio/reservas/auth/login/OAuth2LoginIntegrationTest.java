package com.servicio.reservas.auth.login;

import com.fasterxml.jackson.databind.ObjectMapper;
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
@ActiveProfiles("test")
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
    }

    @Test
    @DisplayName("CA 4: Autenticación Exitosa Password Grant (200 OK con Tokens)")
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
    @DisplayName("CA 5: Autenticación Fallida - Credenciales Incorrectas (400 Invalid Grant)")
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
    @DisplayName("CA 6: Refresco de Token Exitoso (200 OK)")
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
    @DisplayName("CA 7 (Login): Servicio de Usuarios No Disponible")
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
}
