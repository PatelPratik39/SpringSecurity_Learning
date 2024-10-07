package jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.Key;


@Component
public class JwtUtils {

    private static final Logger logger = Logger.getLogger(JwtUtils.class.getName());

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationInMs}")
    private int jwtExpirationInMs;


    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
       logger.info("Bearer token: " + bearerToken);
       if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
           return bearerToken.substring(7);
       }
       return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationInMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            System.out.println("validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(token);
            return true;
        }catch (MalformedJwtException e) {
            logger.log(Level.parse("Invalid JWT token"), e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.log(Level.parse("JWT token is expired : {}"), e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.log(Level.parse("JWT token is unsupported : {}"), e.getMessage());
        } catch (IllegalArgumentException e){
            logger.log(Level.parse("JWT claims string is empty : {}"), e.getMessage());
        }
        return false;
    }

}
