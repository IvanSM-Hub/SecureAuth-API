package com.ivansario.secureauth.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ivansario.secureauth.entity.ObviousPassword;

public interface ObviousPasswordRepository extends JpaRepository<ObviousPassword, UUID> {

    Optional<ObviousPassword> findByObviousPass(String obviousPass);
    boolean existsByObviousPass(String obviousPass);

}
