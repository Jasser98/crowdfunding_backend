package com.rif.authentication.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Token {

    @Id
    @GeneratedValue
    private Long TokenId;

    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @Enumerated(EnumType.STRING)
    private TokenResetPass tokenResetPass;

    private boolean expired;

    private boolean revoked;
    private LocalDateTime expiryDate;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
