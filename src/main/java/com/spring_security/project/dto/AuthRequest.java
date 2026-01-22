package com.spring_security.project.dto;

public record AuthRequest(
        String email,
        String password
) {
}
