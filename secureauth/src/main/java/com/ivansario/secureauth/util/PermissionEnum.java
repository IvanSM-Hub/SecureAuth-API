package com.ivansario.secureauth.util;

public enum PermissionEnum {

    // Profile permissions
    PROFILE_READ("PROFILE_READ"),
    PROFILE_UPDATE("PROFILE_UPDATE"),
    PASSWORD_CHANGE("PASSWORD_CHANGE"),

    // Session permissions
    SESSION_READ("SESSION_READ"),
    SESSION_REVOKE("SESSION_REVOKE"),

    // User management permissions
    USER_READ("USER_READ"),
    USER_CREATE("USER_CREATE"),
    USER_UPDATE("USER_UPDATE"),
    USER_DELETE("USER_DELETE"),

    // Role management permissions
    ROLE_READ("ROLE_READ"),
    ROLE_ASSIGN("ROLE_ASSIGN"),
    ROLE_CREATE("ROLE_CREATE"),
    ROLE_UPDATE("ROLE_UPDATE"),
    ROLE_DELETE("ROLE_DELETE"),

    // Permission management
    PERMISSION_READ("PERMISSION_READ"),
    PERMISSION_ASSIGN("PERMISSION_ASSIGN"),
    PERMISSION_CREATE("PERMISSION_CREATE"),
    PERMISSION_UPDATE("PERMISSION_UPDATE"),
    PERMISSION_DELETE("PERMISSION_DELETE"),

    // Project permissions
    PROJECT_READ("PROJECT_READ"),
    PROJECT_CREATE("PROJECT_CREATE"),
    PROJECT_EDIT("PROJECT_EDIT"),
    PROJECT_DELETE("PROJECT_DELETE"),

    // Audit and security permissions
    AUDIT_READ("AUDIT_READ"),
    SECURITY_MANAGE("SECURITY_MANAGE"),

    // System administration permissions
    SYSTEM_SETTINGS_READ("SYSTEM_SETTINGS_READ"),
    SYSTEM_SETTINGS_UPDATE("SYSTEM_SETTINGS_UPDATE"),
    SYSTEM_MAINTENANCE("SYSTEM_MAINTENANCE");

    private final String displayName;

    PermissionEnum(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
