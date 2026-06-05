package com.ivansario.secureauth.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByToken(String token);

    @EntityGraph(attributePaths = "user")
    List<RefreshToken> findAllByUser(User user);

    void deleteAllByUser(User user);

    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByUser(User user);
}