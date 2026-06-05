package com.ivansario.secureauth.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users_protection")
public class UserProtection {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", unique = true)
    private User user;

    @Column(nullable = false, length = 45)
    private String ipOrigin;

    @Column(nullable = false)
    private int numTrys;

    @Column(nullable = true)
    private LocalDateTime lastTry;

    @Column(nullable = true)
    private LocalDateTime bloquedAt;

    @Column(nullable = false)
    private boolean active;

    @PrePersist
    protected void onCreate() {
        if (lastTry == null) lastTry = LocalDateTime.now();
        if (bloquedAt == null) bloquedAt = null;
        active = bloquedAt != null && bloquedAt.isAfter(LocalDateTime.now());
    }

    @PreUpdate
    protected void onUpdate() {}

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getIpOrigin() {
        return ipOrigin;
    }

    public void setIpOrigin(String ipOrigin) {
        this.ipOrigin = ipOrigin;
    }

    public int getNumTrys() {
        return numTrys;
    }

    public void setNumTrys(int numTrys) {
        this.numTrys = numTrys;
    }

    public LocalDateTime getLastTry() {
        return lastTry;
    }

    public void setLastTry(LocalDateTime lastTry) {
        this.lastTry = lastTry;
    }

    public LocalDateTime getBloquedAt() {
        return bloquedAt;
    }

    public void setBloquedAt(LocalDateTime bloquedAt) {
        this.bloquedAt = bloquedAt;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

}
