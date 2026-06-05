package com.ivansario.secureauth.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ivansario.secureauth.entity.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    @EntityGraph(attributePaths = "role")
    Optional<User> findByUsername(String username);
    @EntityGraph(attributePaths = "role")
    Optional<User> findByEmail(String email);
    
    @EntityGraph(attributePaths = "role")
    @Query("select distinct u from User u left join fetch u.role")
    List<User> findAllWithRoles();
    
    @EntityGraph(attributePaths = "role")
    @Query("select u from User u left join fetch u.role where u.username = :username")
    Optional<User> findByUsernameWithRoles(@Param("username") String username);
    
    @EntityGraph(attributePaths = "role")
    @Query("select u from User u left join fetch u.role where u.email = :email")
    Optional<User> findByEmailWithRoles(@Param("email") String email);
    @EntityGraph(attributePaths = "role")
    boolean existsByUsername(String username);
    @EntityGraph(attributePaths = "role")
    boolean existsByEmail(String email);
}
