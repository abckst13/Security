package com.security.project.utils;

import com.security.project.auth.vo.Users;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;

@Data
@ToString
@Component
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserDetailsImpl implements UserDetails {

    private Users userInfo;

    @Builder
    public UserDetailsImpl(Users users) {
        this.userInfo = users;
    }

//    private UserRole role;
//    private LoginProvider loginProvider;
//    private ProfileImage profileImage;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> grantedAuthority = new ArrayList<>();
//        grantedAuthority.add(new GrantedAuthority() {
//            @Override
//            public String getAuthority() {
//                return getRole().toString();
//            }
//        });

        return grantedAuthority;
    }

    @Override
    public String getUsername() {
        return userInfo.getUserId();
    }

    @Override
    public String getPassword(){ return userInfo.getPassword();}

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
