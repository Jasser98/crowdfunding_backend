package com.rif.community.chat;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api/chat")
public class ChatController {

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    // Endpoint pour envoyer un message
    @PostMapping("/sendMessage")
    public ResponseEntity<ChatMessage> sendMessage(
            @RequestBody ChatMessage chatMessage
    ) {
        // Envoyer le message à tous les abonnés de /topic/public
        messagingTemplate.convertAndSend("/topic/public", chatMessage);
        return ResponseEntity.ok(chatMessage);
    }

    // Endpoint pour ajouter un utilisateur
    @PostMapping("/addUser")
    public ResponseEntity<ChatMessage> addUser(
            @RequestBody ChatMessage chatMessage,
            SimpMessageHeaderAccessor headerAccessor
    ) {
        // Ajouter l'utilisateur dans la session WebSocket
        headerAccessor.getSessionAttributes().put("username", chatMessage.getSender());

        // Envoyer le message à tous les abonnés de /topic/public
        messagingTemplate.convertAndSend("/topic/public", chatMessage);
        return ResponseEntity.ok(chatMessage);
    }
}
