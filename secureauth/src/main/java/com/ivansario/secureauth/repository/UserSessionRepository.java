package com.ivansario.secureauth.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    @EntityGraph(attributePaths = "user")
    List<UserSession> findAllByUser(User user);
    @EntityGraph(attributePaths = "user")
    Optional<UserSession> findByRefreshToken(RefreshToken refreshToken);
    @EntityGraph(attributePaths = "user")
    List<UserSession> findAllByRevoked(boolean revoked);
    void deleteAllByUser(User user);
    @EntityGraph(attributePaths = "user")
    Optional<UserSession> findByUser(User user);
}