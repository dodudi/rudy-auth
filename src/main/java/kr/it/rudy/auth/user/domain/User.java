package kr.it.rudy.auth.user.domain;

import lombok.Getter;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

@Getter
public class User implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final Long id;
    private final String username;
    private final String password;
    private final String nickname;
    private final UserRole userRole;
    private final Instant createdDt;
    private final Instant updatedDt;

    public User(Long id, String username, String password, String nickname, UserRole userRole, Instant createdDt, Instant updatedDt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.nickname = validateNickname(nickname);
        this.userRole = userRole;
        this.createdDt = createdDt;
        this.updatedDt = updatedDt;
    }

    public static User create(String username, String password, String nickname, UserRole userRole) {
        return new User(
                null,
                username,
                password,
                nickname,
                userRole,
                null,
                null
        );
    }

    private static String validateNickname(String nickname) {
        if (nickname != null && !nickname.isBlank()) {
            return nickname;
        }
        return generateRandomNickname();
    }

    private static String generateRandomNickname() {
        String[] adjectives = {"Happy", "Joyful", "Brave", "Wise", "Shining", "Mysterious", "Cool", "Cute"};
        String[] nouns = {"Cat", "Dog", "Rabbit", "Fox", "Bear", "Penguin", "Squirrel", "Owl"};

        String adjective = adjectives[ThreadLocalRandom.current().nextInt(adjectives.length)];
        String noun = nouns[ThreadLocalRandom.current().nextInt(nouns.length)];
        int number = ThreadLocalRandom.current().nextInt(1000);

        return adjective + noun + number;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
