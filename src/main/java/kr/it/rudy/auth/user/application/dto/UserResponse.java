package kr.it.rudy.auth.user.application.dto;

public record UserResponse(
        Long id,
        String username,
        String nickname
) {
}
