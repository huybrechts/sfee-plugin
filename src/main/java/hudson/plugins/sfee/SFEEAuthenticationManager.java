package hudson.plugins.sfee;

import java.util.HashSet;
import java.util.Set;

import hudson.Util;
import org.acegisecurity.*;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;

public class SFEEAuthenticationManager implements AuthenticationProvider {

	private UserDetailsService userDetailsService;

	public SFEEAuthenticationManager(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
			return null;
		}

		String userName = authentication.getName();
		String password = Util.fixEmpty((String) ((UsernamePasswordAuthenticationToken) authentication).getCredentials());

		SFEESecurityRealm.DESCRIPTOR.setPassword(userName,  password);
		UserDetails user = userDetailsService.loadUserByUsername(userName);
		return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());

	}

	public boolean supports(Class authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}
