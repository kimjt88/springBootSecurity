package org.jwt.filter;

import antlr.StringUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import org.jwt.auth.PrincipalDetails;
import org.jwt.model.User;
import org.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    Log logger = LogFactory.getLog(JwtAuthorizationFilter.class);

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        logger.info("권한 인증 시작");


        //인증이 필요하지않은 요청은 넘김
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // 헤더에서 토큰 파싱
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        // 토큰에서 유저명 파싱
        String username = JWT.require(Algorithm.HMAC512("cos"))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();

        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Authentication 객체 강제로 만드는법 Principal 필요
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }

    }
}
