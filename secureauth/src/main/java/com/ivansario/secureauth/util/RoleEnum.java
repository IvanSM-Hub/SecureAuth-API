package com.ivansario.secureauth.util;

public enum RoleEnum {

    ADMIN("admin"),
    USER("user"),
    MANAGER("manager"),
    AUDITOR("auditor");

    private final String displayName;

    RoleEnum(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

}
