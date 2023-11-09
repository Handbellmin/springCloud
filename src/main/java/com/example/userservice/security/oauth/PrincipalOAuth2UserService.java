package com.example.userservice.security.oauth;

import com.example.userservice.jpa.UserRepository;
import com.example.userservice.jpa.Users;
import com.example.userservice.security.auth.PrincipalDetails;
import com.example.userservice.vo.RequestUser;
import com.example.userservice.vo.ResponseUser;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {
    final private UserRepository userRepository;

    final private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest: "+userRequest.getClientRegistration());
        System.out.println("getAccessToken: "+userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("getClientRegistration: "+oAuth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("jmoauth");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        Users users = userRepository.findByEmail(username);
        if (users == null) {
            System.out.println("구글 로그인 회원 가입");
            ModelMapper modelMapper = new ModelMapper();
            RequestUser requestUser = new RequestUser();
            requestUser.setEmail(username);
            requestUser.setPwd(password);
            modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);
            users = modelMapper.map(requestUser, Users.class);
            userRepository.save(users);
        }
        return new PrincipalDetails(users, oAuth2User.getAttributes());
    }




}
