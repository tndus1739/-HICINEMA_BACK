package com.himedia.hicinema.member;


import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.groovy.parser.antlr4.GroovyParser.MemberDeclarationContext;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class MemberSecurityService implements UserDetailsService {
	
	private final MemberRepository memberRepository;
	
	@Override
	public UserDetails loadUserByUsername (String memberId) throws UsernameNotFoundException {
		
		System.out.println("memberId : " + memberId);
		
		Optional<Member> _member = memberRepository.findByMemberId(memberId); 
		
		if(_member.isEmpty()) {
			
			
			throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
		}
		
		Member member = _member.get();
		
		
		
		List<GrantedAuthority> authorities = new ArrayList<>();
		
		if ("admin".equals(memberId)) {
			
			authorities.add( new SimpleGrantedAuthority(MemberRole.ADMIN.getValue()));
			
		} else {
			
			authorities.add( new SimpleGrantedAuthority(MemberRole.USER.getValue()));
		}
		
		return new User (member.getMemberId(), member.getPassword() ,authorities);
//		return User.builder()
//                .username(member.getMemberId())
//                .password(member.getPassword())
//                .roles(member.getRole().toString())
//                .build();
	}
	

}
