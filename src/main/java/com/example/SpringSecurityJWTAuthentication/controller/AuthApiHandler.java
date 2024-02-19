package com.example.SpringSecurityJWTAuthentication.controller;


import com.example.SpringSecurityJWTAuthentication.entity.User;
import com.example.SpringSecurityJWTAuthentication.jwtConfig.JwtService;
import com.example.SpringSecurityJWTAuthentication.modelDTO.AuthResponse;
import com.example.SpringSecurityJWTAuthentication.modelDTO.RequestDTO;
import com.example.SpringSecurityJWTAuthentication.modelDTO.UserDTO;
import com.example.SpringSecurityJWTAuthentication.repository.UserRepo;
import com.example.SpringSecurityJWTAuthentication.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthApiHandler {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    @PostMapping("register")
    public ResponseEntity<AuthResponse>signup(@RequestBody UserDTO userDTO){
        User user=User
                .builder()
                .firstName(userDTO.getFirstName())
                .lastName(userDTO.getLastName())
                .username(userDTO.getUsername())
                .password(passwordEncoder.encode(userDTO.getPassword()))
                .build();

        userRepo.save(user);
        String jwt=jwtService.generateToken(user);
        return new ResponseEntity<>(AuthResponse.builder().jwt(jwt).build(), HttpStatus.OK);
    }

    @PostMapping("login")
    public ResponseEntity<AuthResponse>login(@RequestBody RequestDTO requestDTO){
        authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(requestDTO.getUsername(),requestDTO.getPassword())
        );
        User user= (User) userService.loadUserByUsername(requestDTO.getUsername());
        String jwt=jwtService.generateToken(user);
        return new ResponseEntity<>(AuthResponse.builder().jwt(jwt).build(),HttpStatus.OK);
    }
}
