package kr.it.rudy.auth.user.application.service;

import kr.it.rudy.auth.user.application.dto.UserRequest;
import kr.it.rudy.auth.user.application.dto.UserResponse;
import kr.it.rudy.auth.user.domain.User;
import kr.it.rudy.auth.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional
    public UserResponse createUser(UserRequest request) {
        User user = User.create(request.username(), request.password(), request.nickname());
        User save = userRepository.save(user);
        return new UserResponse(save.getId(), save.getUsername(), save.getNickname());
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(Long id) {
        User user = userRepository.findById(id);
        return new UserResponse(user.getId(), user.getUsername(), user.getNickname());
    }
}
