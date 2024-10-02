package com.rif.authentication.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserRequest {
    private String firstname;
    private String lastname;
    @NotBlank(message = "L'Email doit etre non vide")
    @Email(message = "Email should be valid")
    private String email;
}