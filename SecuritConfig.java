@Configuration //Indicated this is a Spring Configuration class
@EnableWebSecurity	// Enables Spring Security's web security support
@EnableMethodSecurity	// Enables method-level security (eg. @PreAuthorize)
public class SecurityConfig {
	
	private CustomUserDetailsService userDetailsService;
	
	private JwtTokenProvider jwtTokenProvider;
	
	//Constructor Injection: Spring will inject these
	public SecurityConfig(CustomUserDetailsService userDetailsService, JwtTokenProvider jwtTokenProvider) {
		this.jwtTokenProvider = jwtTokenProvider;
		this.userDetailsService = userDetailsService;
	}
	
	//This deines how password will be hashed (encoded) for storage and verification.
	@Bean
	public static PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	//This bean is responsible for performing user authentication.
	//We'll inject this into our AuthController
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
		return configuration.getAuthenticationManager();
	}
	
	//Bean to create our custom JWT authentication filter
	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() {
		//Here we are creating an instance of our filter and injecting its dependencies manually
		return new JwtAuthenticationFilter(jwtTokenProvider, userDetailsService);
	}
	
	//This defines the security rules for incoming HTTP requests.
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		http
			.csrf(csrf -> csrf.disable())
//			.cors(Customizer.withDefaults())
			.cors(cors -> cors.configurationSource(corsConfigurationSource())) // <-- ADD THIS LINE INSTEAD
			.authorizeHttpRequests(authorize -> 
				authorize
					//Allow unauthenticated access to the authentication endpoints
					.requestMatchers("/api/auth/**").permitAll()
					//Allow unauthenticated access to Swagger UI documentation
					.requestMatchers("/v33/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
					//All other requests require authentication
					.anyRequest().authenticated()
			)
			// Configure session management to be stateless
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		//JWT filter will be added here later
		http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
		
		return http.build(); //Build and return configured SecurityFilterChain
	}
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200")); // Allow your Angular app's origin
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Allow common HTTP methods
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type")); // Allow necessary headers
        configuration.setAllowCredentials(true); // Allow sending cookies/auth headers
        configuration.setMaxAge(3600L); // Max age for preflight OPTIONS request cache

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Apply this CORS config to all paths
        return source;
    }
}
