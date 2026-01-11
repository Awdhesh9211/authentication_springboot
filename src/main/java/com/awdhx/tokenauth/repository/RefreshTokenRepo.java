package com.awdhx.tokenauth.repository;

import com.awdhx.tokenauth.entity.RefreshToken;
import com.awdhx.tokenauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(User user);
}

