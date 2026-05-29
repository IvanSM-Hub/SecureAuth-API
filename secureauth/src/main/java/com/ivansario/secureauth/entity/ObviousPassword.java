package com.ivansario.secureauth.entity;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "obvious_passwords")
public class ObviousPassword {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotBlank(message = "Obvious password is required")
    @Size(max = 255, message = "Obvious password cannot exceed 255 characters")
    @Column(name = "obvious_pass", nullable = false, length = 255, unique = true)
    private String obviousPass;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getObviousPass() {
        return obviousPass;
    }

    public void setObviousPass(String obviousPass) {
        this.obviousPass = obviousPass;
    }

}