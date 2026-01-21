package kr.it.rudy.auth.user.infrastructure.jpa;

import kr.it.rudy.auth.user.domain.User;
import kr.it.rudy.auth.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class UserRepositoryImpl implements UserRepository {

    private final JpaUserRepository userRepository;

    @Override
    public User save(User user) {
        UserEntity userEntity = UserEntity.from(user);
        return userRepository.save(userEntity).toDomain();
    }

    @Override
    public User findById(Long id) {
        return userRepository.findById(id)
                .map(UserEntity::toDomain)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(UserEntity::toDomain)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }
}
