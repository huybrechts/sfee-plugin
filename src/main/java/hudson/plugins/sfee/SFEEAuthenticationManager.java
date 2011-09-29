package hudson.plugins.sfee;

import java.util.HashSet;
import java.util.Set;

import hudson.Util;
import org.acegisecurity.*;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
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

		if (password != null && password.equals(SFEESecurityRealm.DESCRIPTOR.getPassword(userName))) {
			return authentication;
		}

		String sessionId = SourceForgeSite.DESCRIPTOR.getSite().createSession(userName, password);
		SFEESecurityRealm.DESCRIPTOR.setPassword(userName,  password);

		return authentication;


	}

	public boolean supports(Class authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}
