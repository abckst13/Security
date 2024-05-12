package com.security.project.utils;

import com.security.project.auth.query.UserQuery;
import com.security.project.auth.vo.Users;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserQuery userQuery;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = Optional.of(userQuery.userInfo(username))
                .orElseThrow(() -> new IllegalArgumentException(username));
        return new UserDetailsImpl(users);
    }
}
