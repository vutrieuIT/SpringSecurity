package com.example.springsecurity.config;

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
// tạo, kiểm tra và trích xuất thông tin từ token JWT,
public class JwtService {

    private static final String SECRET_KEY = "HDFHASDFLGEUGFGBASDUIFGEUGIUFADFGHDHJSGFUE326V23J1";

    // lấy username từ token
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // sinh token theo userDetail
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    // sinh token với tên người dùng, thời điểm cấp, thời điểm hết hạn
    // được ký với secretkey bằng thuật HS256
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    // kiểm tra token có giá trị sử dụng hay không
    // với username và thời hạn token
    public boolean isTokenValue(String token, UserDetails userDetails){
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // kiểm tra xem token có hết hạn hay không
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // trích xuất thông tin thời gian hết hạn (expiration time) từ token JWT
    // bằng cách sử dụng hàm (Function) Claims::getExpiration.
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // trích xuất một claim (thông tin) cụ thể từ token JWT
    // bằng cách sử dụng hàm (Function) claimsResolver
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // trích xuất tất cả các claim từ token JWT
    // và trả về đối tượng Claims chứa thông tin của chúng.
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // tạo byte key cho sign token
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
