package kr.it.rudy.auth.user.application.dto;

import jakarta.validation.constraints.NotBlank;
import kr.it.rudy.auth.user.domain.UserRole;

public record UserRequest(
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Password is required")
        String password,

        String nickname,

        UserRole userRole
) {
}
