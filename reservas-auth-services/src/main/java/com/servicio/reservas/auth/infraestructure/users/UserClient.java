package com.servicio.reservas.auth.infraestructure.users;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Optional;

@FeignClient(name = "reservas-usuarios-service", configuration = UserClientConfig.class)
public interface UserClient {
    @PostMapping("/api/users/create")
    UserDTO create(@RequestBody RegisterRequest registerRequest);

    @GetMapping("/api/users/email/{email}")
    Optional<UserDTO> findByEmail(@PathVariable String email);
}

