@Service
public class CustomUserDetailsService implements UserDetailsService {
  private UserRepository userRepository;
	
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
		Users user = userRepository.findByUserName(username)
				.orElseGet(() -> userRepository.findByEmail(username)
						.orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: "+username)));
String roleString = user.getRole().name();
System.out.println("CustomUserDetailsService: User loaded: " + user.getUserName() + ", Raw Role: "+roleString + ", Spring Security Role: ROLE_"+roleString);
Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
		return new org.springframework.security.core.userdetails.User(
				user.getUserName(),
				user.getPassword(),
				authorities
		);
  }
}
