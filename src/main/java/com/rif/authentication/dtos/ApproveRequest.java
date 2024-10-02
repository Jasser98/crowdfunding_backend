package com.rif.authentication.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class ApproveRequest {
    @NotEmpty(message = "L'email ne doit pas être vide.")
    @Email(message = "L'email doit être valide.")
    private String email;
}
