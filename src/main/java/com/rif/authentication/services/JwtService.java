package com.rif.authentication.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service

public class JwtService {
    private static final String SECRET_KEY = "2b07b8e2d1f9261f3c40b7f97d2d3f7b6c142ca8ae98d48e0a0b7c7a56a3e4d5";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // extract username ml token
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { // this method for extract a single claim tha we pass
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken (
            Map<String, Object> extractClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // help as to calculate the expiration date or to check the token is valid or not
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 )) // my token valid for 24h + 1000ms
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // generate and return the token
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return  (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return  extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) // wa9t me nheb create wela decode the token we need to use the signIn key
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
