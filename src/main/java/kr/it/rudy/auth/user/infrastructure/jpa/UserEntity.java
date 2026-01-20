package kr.it.rudy.auth.user.infrastructure.jpa;

import jakarta.persistence.*;
import kr.it.rudy.auth.user.domain.User;
import kr.it.rudy.auth.user.domain.UserRole;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
public class UserEntity extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false)
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "nickname", nullable = false)
    private String nickname;

    public UserEntity(Long id, String username, String password, String nickname) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.nickname = nickname;
    }

    public static UserEntity from(User user) {
        return new UserEntity(user.getId(), user.getUsername(), user.getPassword(), user.getNickname());
    }

    public User toDomain() {
        return new User(id, username, password, nickname, getCreatedDt(), getUpdatedDt());
    }
}
