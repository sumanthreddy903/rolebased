@Component
public class JwtTokenProvider {
@Value("${jwt.secret}")  //Injects the secret key from application.properties
	private String jwtSecret;
	
@Value("${jwt.expiration.milliseconds}") //Injects the expiration time from application.properties
	private long jwtExpirationDate;

public String generateToken(Authentication authentication) {
		String username = authentication.getName();
		
		//Extract roles from the authentication object
		String roles = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));  //Join roles by comma
															
		
		Date currentDate = new Date();
		Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);
		
		String token = Jwts.builder()
				.setSubject(username)  
				.claim("roles", roles)
				.setIssuedAt(new Date()) 
				.setExpiration(expireDate) 
				.signWith(key())  
				.compact();  //Build and compact the token
		return token;
}

private Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));  //Decode base64 secret to a key
}

public String getUserName(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(key())
				.build()
				.parseClaimsJws(token)
				.getBody();
		return claims.getSubject();
}
public boolean validateToken(String token) {
try {
			Jwts.parserBuilder()
				.setSigningKey(key())
				.build()
				.parse(token);
			return true;
		}
}
}
