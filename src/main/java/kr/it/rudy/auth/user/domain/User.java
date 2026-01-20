package kr.it.rudy.auth.user.domain;

import lombok.Getter;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

@Getter
public class User {
    private final Long id;
    private final String username;
    private final String password;
    private final String nickname;
    private final Instant createdDt;
    private final Instant updatedDt;

    public User(Long id, String username, String password, String nickname, Instant createdDt, Instant updatedDt) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.nickname = validateNickname(nickname);
        this.createdDt = createdDt;
        this.updatedDt = updatedDt;
    }

    public static User create(String username, String password, String nickname) {
        return new User(
                null,
                username,
                password,
                nickname,
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
        String[] adjectives = {"행복한", "즐거운", "용감한", "지혜로운", "빛나는", "신비로운", "멋진", "귀여운"};
        String[] nouns = {"고양이", "강아지", "토끼", "여우", "곰돌이", "펭귄", "다람쥐", "부엉이"};

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
