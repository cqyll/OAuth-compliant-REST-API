package io.github.cqyll.todoapi.dto;

public record RegisterResponse(String id, String email, String name, boolean active, boolean emailVerified) {}
