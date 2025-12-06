package com.servicio.reservas.auth.register;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.servicio.reservas.auth.TestSecurityConfig;
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
import org.springframework.context.annotation.Import;
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
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
public class RegisterIntegrationTest {
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
                .build();

        mockUserDto = new UserDTO();
        mockUserDto.setId(1L);
        mockUserDto.setEmail("juan@test.com");
        mockUserDto.setPassword(passwordEncoder.encode("password123"));
        mockUserDto.setRole(Role.CLIENTE.toString());
        mockUserDto.setName("Juan Perez");
    }

    /**
     * Test 1: Registro Exitoso (201 Created).
     * <p>
     * Verifica el "Happy Path" del proceso de registro de usuarios.
     * <p>
     * El sistema debe:
     * 1. Recibir una solicitud de registro con datos válidos (DTO {@link RegisterRequest}).
     * 2. Delegar la creación al microservicio de usuarios (simulado por el mock {@link UserClient}).
     * 3. Recibir la confirmación de creación (DTO {@link UserDTO}).
     * 4. Responder al cliente con un estado HTTP 201 Created.
     */
    @Test
    @DisplayName("Test 1: Registro Exitoso (201 Created)")
    void testRegisterSuccess() throws Exception {
        when(userClient.create(any(RegisterRequest.class))).thenReturn(mockUserDto);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isCreated());
    }

    /**
     * Test 2: Validación de Registro - Datos Inválidos (400 Bad Request).
     * <p>
     * Verifica que la capa de validación (Bean Validation / Hibernate Validator) intercepte
     * datos incorrectos antes de procesar cualquier lógica de negocio.
     * <p>
     * Escenario:
     * 1. Se envía un email con formato incorrecto ("not-an-email").
     * 2. Se envía una contraseña demasiado corta.
     * 3. El controlador debe rechazar la petición inmediatamente con un 400 Bad Request.
     * 4. La respuesta debe contener detalles sobre los campos erróneos ("errors.email", "errors.password").
     */
    @Test
    @DisplayName("Test 2: Validación de Registro con Datos Inválidos (400 Bad Request)")
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

    /**
     * Test 3: Usuario Ya Existe (422 Unprocessable Entity).
     * <p>
     * Verifica el manejo de conflictos de unicidad (ej. email duplicado).
     * <p>
     * Escenario:
     * 1. El {@link UserClient} (mock) lanza una {@link UserAlreadyExistsException}, simulando
     * que el microservicio de usuarios rechazó la creación por duplicidad.
     * 2. El servicio de autenticación debe capturar esta excepción de negocio.
     * 3. Debe transformar la excepción en una respuesta HTTP 422 Unprocessable Entity estándar.
     */
    @Test
    @DisplayName("Test 3: Usuario Ya Existe (422 Unprocessable Entity)")
    void testRegisterUserAlreadyExists() throws Exception {
        when(userClient.create(any(RegisterRequest.class)))
                .thenThrow(new UserAlreadyExistsException("User already exists"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isUnprocessableEntity());
    }

    /**
     * Test 4: Servicio de Usuarios No Disponible (503 Service Unavailable).
     * <p>
     * Verifica la resiliencia del sistema cuando una dependencia crítica falla.
     * <p>
     * Escenario:
     * 1. El {@link UserClient} falla al intentar conectar con el microservicio de usuarios
     * (lanzando {@link ServiceUnavailableException}).
     * 2. El servicio de autenticación no debe "explotar" con un error 500 genérico.
     * 3. Debe capturar el fallo y responder con un 503 Service Unavailable, indicando
     * al cliente que el problema es temporal y del lado del servidor.
     */
    @Test
    @DisplayName("Test 4: Servicio de Usuarios No Disponible (503)")
    void testRegisterServiceUnavailable() throws Exception {
        when(userClient.create(any(RegisterRequest.class)))
                .thenThrow(new ServiceUnavailableException("Service Unavailable"));

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRegisterRequest)))
                .andExpect(status().isServiceUnavailable());
    }
}
