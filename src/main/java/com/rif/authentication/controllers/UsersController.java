package com.rif.authentication.controllers;

import com.rif.authentication.dtos.ChangePasswordRequest;
import com.rif.authentication.dtos.UpdateUserRequest;
import com.rif.authentication.dtos.UpdateUserResponse;
import com.rif.authentication.services.UsersService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {

    private final UsersService usersService;


    @GetMapping("/info")
    public ResponseEntity<UpdateUserResponse> getConnectedUserInfo(Principal connectedUser) {
        return ResponseEntity.ok(usersService.userInfo(connectedUser));
    }

    @PutMapping("/update")
    public ResponseEntity<UpdateUserResponse> updateUser(
            @Valid @RequestBody UpdateUserRequest updatedUserRequest,
            Principal connectedUser
    ) {
        return ResponseEntity.ok(usersService.updateUser(updatedUserRequest, connectedUser));
    }


    @PostMapping("/changePassword")
    public ResponseEntity<?> changePassword (
            @RequestBody ChangePasswordRequest request,
            Principal connectedUser
    ) throws IllegalAccessException {
        usersService.changePassword(request,connectedUser);
        return ResponseEntity.ok().build();
    }

}
