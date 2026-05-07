package com.ivansario.secureauth.util;

public enum RoleEnum {

    ADMIN("ROLE_ADMIN"),
    USER("ROLE_USER"),
    MANAGER("ROLE_MANAGER"),
    AUDITOR("ROLE_AUDITOR");

    private final String displayName;

    RoleEnum(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

}
