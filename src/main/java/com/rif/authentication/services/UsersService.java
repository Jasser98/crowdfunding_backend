package com.rif.authentication.services;

import com.rif.authentication.dtos.ChangePasswordRequest;
import com.rif.authentication.dtos.UpdateUserRequest;
import com.rif.authentication.dtos.UpdateUserResponse;
import com.rif.authentication.exceptions.*;
import com.rif.authentication.models.User;
import com.rif.authentication.repositorys.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class UsersService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";


    // Get information for the connected user
    public UpdateUserResponse userInfo(Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        if (user == null) {
            throw new UserNotFoundException(user.getId());
        }

        return new UpdateUserResponse(
                user.getFirstname(),
                user.getLastname(),
                user.getEmail()
        );
    }

    // Update user
    public UpdateUserResponse updateUser(UpdateUserRequest updatedUserRequest, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        if (user == null) {
            throw new UserNotFoundException(user.getId());
        }

        // Check if email is valid
        if (!Pattern.matches(EMAIL_REGEX, updatedUserRequest.getEmail())) {
            throw new InvalidEmailException();
        }

        // Check if email is already in use
        if (userRepository.findByEmail(updatedUserRequest.getEmail()).isPresent() &&
                !user.getEmail().equals(updatedUserRequest.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        user.setFirstname(updatedUserRequest.getFirstname());
        user.setLastname(updatedUserRequest.getLastname());
        user.setEmail(updatedUserRequest.getEmail());

        userRepository.save(user);

        return new UpdateUserResponse(
                user.getFirstname(),
                user.getLastname(),
                user.getEmail()
        );
    }

    // Change password
    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        if (user == null) {
            throw new UserNotFoundException(user.getId());
        }

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new InvalidPasswordException();
        }

        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new PasswordMismatchException();
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
}
