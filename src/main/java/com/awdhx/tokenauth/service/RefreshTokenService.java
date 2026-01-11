package com.awdhx.tokenauth.service;

import com.awdhx.tokenauth.entity.RefreshToken;
import com.awdhx.tokenauth.entity.User;
import com.awdhx.tokenauth.repository.RefreshTokenRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    RefreshTokenRepo repo;

    public RefreshToken create(User user) {

        // 🔥 Step 1: Agar is user ka pehle se token hai, delete karo
        repo.findByUser(user).ifPresent(repo::delete);

        // 🔑 Step 2: Naya refresh token banao
        RefreshToken token = new RefreshToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(user);
        token.setExpiryDate(Instant.now().plus(7, ChronoUnit.DAYS));

        return repo.save(token);
    }

    public RefreshToken verify(String token) {
        RefreshToken rt = repo.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (rt.getExpiryDate().isBefore(Instant.now())) {
            // Token expired, delete it from DB
            repo.delete(rt);
            throw new RuntimeException("Refresh token expired");
        }

        return rt;
    }

}


