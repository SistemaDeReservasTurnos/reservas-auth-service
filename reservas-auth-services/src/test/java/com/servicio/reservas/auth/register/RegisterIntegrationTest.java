package com.servicio.reservas.auth.register;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicio.reservas.auth.application.dto.RegisterRequest;
import com.servicio.reservas.auth.application.exceptions.ServiceUnavailableException;
import com.servicio.reservas.auth.application.exceptions.UserAlreadyExistsException;
import com.servicio.reservas.auth.domain.entities.Role;
import com.servicio.reservas.auth.infraestructure.users.UserClient;
import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegisterIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private UserClient userClient;

    private RegisterRequest validRegisterRequest;
    private UserDTO mockUserDto;

    @BeforeEach
    void setUp() {
        validRegisterRequest = RegisterRequest.builder()
                .name("Juan Perez")
                .email("juan@test.com")
                .password("password123")
                .phone_number("1234567890")
                .role(Role.CLIENTE.toString())
                .build();

        mockUserDto = new UserDTO();
        mockUserDto.setId(1L);
        mockUserDto.setEmail("juan@test.com");
        mockUserDto.setPassword(passwordEncoder.encode("password123"));
        mockUserDto.setRole(Role.CLIENTE.toString());
        mockUserDto.setName("Juan Perez");
    }

    @Test
    @DisplayName("CA 1: Registro Exitoso (201 Created)")
    void testRegisterSuccess() throws Exception {
        when(userClient.create(any(RegisterRequest.class))).thenReturn(mockUserDto);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("CA 2: Validación de Registro - Datos Inválidos (400 Bad Request)")
    void testRegisterValidationFailure() throws Exception {
        RegisterRequest invalidRequest = RegisterRequest.builder()
                .email("not-an-email")
                .password("123")
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    @DisplayName("CA 3: Usuario Ya Existe (409 Conflict)")
    void testRegisterUserAlreadyExists() throws Exception {
        when(userClient.create(any(RegisterRequest.class)))
                .thenThrow(new UserAlreadyExistsException("User already exists"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("CA 7 (Registro): Servicio de Usuarios No Disponible (503)")
    void testRegisterServiceUnavailable() throws Exception {
        when(userClient.create(any(RegisterRequest.class)))
                .thenThrow(new ServiceUnavailableException("Service Unavailable"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isServiceUnavailable());
    }
}
