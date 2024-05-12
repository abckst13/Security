package com.security.project.auth.service;

import com.security.project.auth.query.UserQuery;
import com.security.project.auth.vo.Users;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserQuery userQuery;

    public String userJoin(Users users) throws Exception {
        String result = "";
        Users userInfo = userQuery.userFind(users);
        if (userInfo == null ) {
            try {
                userQuery.userJoin(users);
                result = "200";
            } catch (Exception e) {
                log.error("Error ====> {}", e.getMessage());
            }
        } else {
            throw new Exception();
        }
        return result;
    }

    public Optional<Users> findByRefreshToken(String refreshToken) {
       Optional<Users> userInfo = Optional.of(Optional.of(userQuery.findByRefreshTokenUserInfo(refreshToken)).orElseThrow());
       return userInfo;
    }

    public Users userInfo(String userId) {

        return userQuery.userInfo(userId);
    }
}
