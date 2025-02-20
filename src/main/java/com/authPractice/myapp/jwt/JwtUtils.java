package com.authPractice.myapp.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.hibernate.boot.model.naming.IllegalIdentifierException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;




@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private long jwtExpirationMs;



    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken =  request.getHeader("Authorization");
        logger.debug("Authorization Header: {}" , bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        logger.error("Bearer Token Error: {}" ,bearerToken);
        return null;
    }

    public String getUsernameFromToken(UserDetails userDetails){
        String username = userDetails.getUsername();
        String token = Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
        logger.debug("genrated token genratefromusername: {}" , token);
        return token;
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
//jhsajdhaskhdkjahd
    public String getUsernameFromToken(String token){
        logger.debug("genrated token : {}" , token);
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateJwtToken(String token){
        try{
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey)key()).build().parseSignedClaims(token);
            return true;
        }catch (MalformedJwtException e){
            logger.error("Invalid JWT token :{}",e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT token Expired :{}", e.getMessage());
        }catch (UnsupportedJwtException e){
            logger.error("JWT token is unsupported : {}" , e.getMessage());
        }catch (IllegalIdentifierException e){
            logger.error("JWT claims string is empty :{}" , e.getMessage());
        }
        return false;
    }
}
