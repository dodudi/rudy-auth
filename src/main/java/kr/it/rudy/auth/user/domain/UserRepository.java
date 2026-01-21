package kr.it.rudy.auth.user.domain;

import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository {
    User save(User user);

    User findById(Long id);

    User findByUsername(String username);
}
