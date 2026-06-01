package com.ivansario.secureauth.security;

import java.io.IOException;

import io.jsonwebtoken.JwtException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ivansario.secureauth.entity.RefreshToken;
import com.ivansario.secureauth.entity.User;
import com.ivansario.secureauth.entity.UserSession;
import com.ivansario.secureauth.service.interfaces.RefreshTokenService;
import com.ivansario.secureauth.service.interfaces.UserService;
import com.ivansario.secureauth.service.interfaces.UserSessionService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Request filter that validates the JWT for incoming requests.
 *
 * Extracts the Bearer token from the Authorization header and sets the
 * authentication in the security context if the token is valid.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final UserSessionService userSessionService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Main filter handling:
     * - Extracts and validates the Bearer token
     * - Sets authentication in the SecurityContext if the token is valid
     */
    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {


        String requestPath = request.getRequestURI();
        
        String authHeader = request.getHeader("Authorization");
        String token;
        String useremail;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("JWT filter skipped for {} because Authorization header is missing or malformed", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        token = authHeader.substring(7);
        try {
            useremail = jwtUtil.extractUsername(token);
            log.debug("JWT subject extracted for {}: {}", requestPath, useremail);
        } catch (JwtException ex) {
            log.warn("JWT parsing failed for {}", requestPath, ex);
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
            return;
        }

        if (useremail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                UserDetails userDetails = userService.loadUserByUsername(useremail);
                User user = userService.findUser(useremail);
                if (jwtUtil.isTokenValid(token, userDetails) && isSessionValid(user)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, 
                        null,
                        userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("JWT authentication established for {} with authorities {}", useremail, userDetails.getAuthorities());
                } else {
                    log.warn("JWT validation failed for {}", useremail);
                    throw new JwtException("Invalid JWT token for user: " + useremail);
                }
            } catch (JwtException | UsernameNotFoundException ex) {
                log.warn("JWT authentication failed for {}", useremail, ex);
                SecurityContextHolder.clearContext();
            } catch (RuntimeException ex) {
                log.warn("JWT authentication failed for {} due to runtime exception", useremail, ex);
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);

    }

    private boolean isSessionValid(User user) {
        UserSession session = userSessionService.findByUser(user);
        if (session == null || session.isRevoked()) {
            return false;
        }

        RefreshToken refreshToken = refreshTokenService.findByUser(user);
        if (refreshToken == null) {
            return false;
        }

        return !refreshToken.isRevoked() && !refreshToken.isExpired() && user.isEnabled();
    }

}
