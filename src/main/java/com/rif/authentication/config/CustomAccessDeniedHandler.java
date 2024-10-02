package com.rif.authentication.config;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;


import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {


    @Override
    public void handle(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, jakarta.servlet.ServletException {
        // Configure le code de statut HTTP
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // Configure le type de contenu de la réponse
        response.setContentType("application/json");

        // Ajoute un message d'erreur personnalisé
        response.getWriter().write("{ \"error\": \"Vous n'avez pas les permissions pour effectuer cette tâche.\" }");
    }
}

