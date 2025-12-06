package com.servicio.reservas.auth.infraestructure.config;

import com.servicio.reservas.auth.infraestructure.users.UserDTO;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import java.util.List;

@Getter
public class CustomUserDetails extends User {
    private final Long id;
    private final String name;
    private final String email;

    public CustomUserDetails(UserDTO userDTO) {
        super(
                userDTO.getEmail(),
                userDTO.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_" + userDTO.getRole().toUpperCase()))
        );

        this.id = userDTO.getId();
        this.name = userDTO.getName();
        this.email = userDTO.getEmail();
    }
}
