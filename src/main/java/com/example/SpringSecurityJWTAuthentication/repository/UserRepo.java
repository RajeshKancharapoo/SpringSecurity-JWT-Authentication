package com.example.SpringSecurityJWTAuthentication.repository;

import com.example.SpringSecurityJWTAuthentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User,Integer> {

    Optional<User> findByUsername(String username);
}
