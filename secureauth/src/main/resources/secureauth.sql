CREATE TABLE "users" (
  "id" CHAR(36) PRIMARY KEY,
  "username" VARCHAR(100) NOT NULL UNIQUE,
  "email" VARCHAR(255) NOT NULL UNIQUE,
  "password_hash" VARCHAR(255) NOT NULL,
  "enabled" BOOLEAN DEFAULT TRUE,
  "created_at" DATETIME DEFAULT CURRENT_TIMESTAMP,
  "updated_at" DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  "last_login" DATETIME
);

CREATE TABLE "roles" (
  "id" CHAR(36) PRIMARY KEY,
  "name" VARCHAR(100) NOT NULL UNIQUE,
  "description" VARCHAR(255)
);

CREATE TABLE "permission" (
  "id" CHAR(36) PRIMARY KEY,
  "name" VARCHAR(100) NOT NULL UNIQUE,
  "description" VARCHAR(255)
);

CREATE TABLE "role_permissions" (
  "id" CHAR(36) PRIMARY KEY,
  "role_id" CHAR(36) NOT NULL,
  "permission_id" CHAR(36) NOT NULL,
  FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON DELETE CASCADE,
  FOREIGN KEY ("permission_id") REFERENCES "permission" ("id") ON DELETE CASCADE
);

CREATE TABLE "user_roles" (
  "id" CHAR(36) PRIMARY KEY,
  "user_id" CHAR(36) NOT NULL,
  "role_id" CHAR(36) NOT NULL,
  FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
  FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON DELETE CASCADE
);

CREATE TABLE "refresh_tokens" (
  "id" CHAR(36) PRIMARY KEY,
  "user_id" CHAR(36) NOT NULL,
  "token" VARCHAR(500) NOT NULL UNIQUE,
  "expiry_date" DATETIME NOT NULL,
  "revoked" BOOLEAN DEFAULT FALSE,
  "created_at" DATETIME DEFAULT CURRENT_TIMESTAMP,
  "ip_address" VARCHAR(45),
  "user_agent" VARCHAR(255),
  FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE TABLE "user_sessions" (
  "id" CHAR(36) PRIMARY KEY,
  "user_id" CHAR(36) NOT NULL,
  "refresh_token_id" CHAR(36) NOT NULL,
  "ip_address" VARCHAR(45),
  "device_info" VARCHAR(255),
  "created_at" DATETIME DEFAULT CURRENT_TIMESTAMP,
  "last_activity" DATETIME DEFAULT CURRENT_TIMESTAMP,
  "revoked" BOOLEAN DEFAULT FALSE,
  FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE,
  FOREIGN KEY ("refresh_token_id") REFERENCES "refresh_tokens" ("id") ON DELETE CASCADE
);