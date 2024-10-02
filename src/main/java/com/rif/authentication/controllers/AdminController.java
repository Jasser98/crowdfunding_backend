package com.rif.authentication.controllers;

import com.rif.authentication.dtos.UserResponse;
import com.rif.authentication.services.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        List<UserResponse> users = adminService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable Long id) {
        return adminService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/user/approve/{id}")
    public ResponseEntity<String> approveUser(@PathVariable Long id) {
        String message = adminService.approveUser(id);
        return ResponseEntity.ok(message);
    }

    @PostMapping("/user/disapprove/{id}")
    public ResponseEntity<String> disapproveUser(@PathVariable Long id) {
        String message = adminService.disapproveUser(id);
        return ResponseEntity.ok(message);
    }

    @DeleteMapping("/user/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        String message = adminService.deleteUser(id);
        return ResponseEntity.ok(message);
    }
}
