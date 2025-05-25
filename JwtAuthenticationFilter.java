public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private JwtTokenProvider jwtTokenProvider;
	
	private CustomUserDetailsService customUserDetailsService;
	
	public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, CustomUserDetailsService customUserDetailsService) {
		this.jwtTokenProvider = jwtTokenProvider;
		this.customUserDetailsService = customUserDetailsService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		
		// 1. Get JWT token from HTTP request
		String token = getTokenFromRequest(request);
		
		
		//2. Validate token and load user details
		if(StringUtils.hasText(token) & jwtTokenProvider.validateToken(token)) {
			// Get username from token
			String username = jwtTokenProvider.getUserName(token);
			
			//Load user associated with token
			UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
			
			//Create an authentication object
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				userDetails,
				null, // No credentials needed here as token is already validated
				userDetails.getAuthorities()  //Get roles/authorities from UserDetails
			);
			
			//Set web authentication details (e.g., remote IP address
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
			//Set Spring Security authentication in the SecurityContext
			//This is crucial: it tells Spring Seurity who the current authenticated user is.
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		}
		
		//3. Continue with the filter chain (pass request to next filter/controller)
		filterChain.doFilter(request, response);
	}
	
	
	//Helper method to extract JWT from Authorization header
	private String getTokenFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");  //Get the Authorization header
		
		//Check if header exists and status with "Bearer "
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length()); //Extract token after "Bearer "
		}
		return null;  //No Token Found
	}

}
