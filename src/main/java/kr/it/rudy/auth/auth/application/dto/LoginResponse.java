package kr.it.rudy.auth.auth.application.dto;

public record LoginResponse(
        String message,
        String username,
        String sessionId
) {
}
