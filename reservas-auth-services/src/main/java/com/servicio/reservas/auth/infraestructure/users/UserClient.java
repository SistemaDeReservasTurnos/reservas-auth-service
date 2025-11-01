package com.servicio.reservas.auth.infraestructure.users;

import com.servicio.reservas.auth.application.dto.RegisterRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "reservas-usuarios-service")
public interface UserClient {
    @PostMapping("/api/users/create")
    UserDTO create(@RequestBody RegisterRequest registerRequest);
}
