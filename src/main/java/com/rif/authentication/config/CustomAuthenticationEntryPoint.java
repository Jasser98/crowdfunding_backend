package com.rif.authentication.config;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {



    @Override
    public void commence(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, AuthenticationException authException) throws IOException, jakarta.servlet.ServletException {
        // Configure le code de statut HTTP pour non authentifié
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Configure le type de contenu de la réponse
        response.setContentType("application/json");

        // Ajoute un message d'erreur personnalisé
        response.getWriter().write("{ \"error\": \"Vous devez être authentifié pour accéder à cette ressource.\" }");
    }
}
