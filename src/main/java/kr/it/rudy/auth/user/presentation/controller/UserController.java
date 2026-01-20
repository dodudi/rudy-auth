package kr.it.rudy.auth.user.presentation.controller;

import jakarta.validation.Valid;
import kr.it.rudy.auth.user.application.dto.UserRequest;
import kr.it.rudy.auth.user.application.dto.UserResponse;
import kr.it.rudy.auth.user.application.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody UserRequest request
    ) {
        UserResponse user = userService.createUser(request);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> getUser(
            @PathVariable Long id
    ) {
        UserResponse user = userService.getUser(id);
        return ResponseEntity.ok(user);
    }
}
