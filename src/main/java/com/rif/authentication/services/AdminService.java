package com.rif.authentication.services;

import com.rif.authentication.dtos.UserResponse;
import com.rif.authentication.exceptions.UserNotFoundException;
import com.rif.authentication.models.Token;
import com.rif.authentication.models.User;
import com.rif.authentication.repositorys.TokenRepository;
import com.rif.authentication.repositorys.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class AdminService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;

    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(user -> new UserResponse(
                        user.getId(),
                        user.getFirstname(),
                        user.getLastname(),
                        user.getEmail(),
                        user.getRole().name(),
                        user.getApproved()
                ))
                .collect(Collectors.toList());
    }

    public Optional<UserResponse> getUserById(Long id) {
        User user = findUserById(id);
        return Optional.of(new UserResponse(
                user.getId(),
                user.getFirstname(),
                user.getLastname(),
                user.getEmail(),
                user.getRole().name(),
                user.getApproved()
        ));
    }


    @Transactional
    public String approveUser(Long id) {
        return changeUserApprovalStatus(id, true, "Compte Activé", "Votre compte a été activé.");
    }

    @Transactional
    public String disapproveUser(Long id) {
        return changeUserApprovalStatus(id, false, "Compte désactivé", "Votre compte a été désactivé.");
    }

    private String changeUserApprovalStatus(Long id, boolean status, String subject, String messageBody) {
        var user = findUserById(id);
        user.setApproved(status);
        userRepository.save(user);

        emailService.sendEmail(user.getEmail(), subject,
                "Cher " + user.getFirstname() + ",\n\n" + messageBody + "\n\nCordialement,\n\nRIF : RASSEMBLEMENT DES INGÉNIEURS FRANCOPHONES,\ngrouperif.com");

        return "Utilisateur avec l'ID " + id + " a été " + (status ? "activé" : "désactivé") + " avec succès.";
    }

    @Transactional
    public String deleteUser(Long id) {
        var user = findUserById(id);

        List<Token> tokens = tokenRepository.findAllValidTokensByUser(id);
        tokenRepository.deleteAll(tokens);

        userRepository.delete(user);

        emailService.sendEmail(user.getEmail(), "Compte supprimé",
                "Cher " + user.getFirstname() + ",\n\nVotre compte a été supprimé par l'administrateur de notre site web.\n\nCordialement,\n\nRIF : RASSEMBLEMENT DES INGÉNIEURS FRANCOPHONES,\ngrouperif.com");

        return "Utilisateur avec l'ID " + id + " a été supprimé avec succès.";
    }

    private User findUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }
}
