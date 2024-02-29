package com.himedia.hicinema.member;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class MemberTest {

	
	@Autowired    // 객체 주입
	private MemberRepository memberRepository ;
	
	@Test
	public void memberTest () {
		
		// Insert test
		Member m1 = new Member();
		m1.setName("sooo");
		m1.setMemberId("user11");
		m1.setPassword("1234");
		m1.setPhone("010-1234-1234");
		m1.setEmail("aaa@aaa.com");
		m1.setRegdate(LocalDateTime.now());
		m1.setRole("user");
		
		System.out.println("m1 : "+ m1);
		this.memberRepository.save(m1);
		
		Member m2 = new Member();
		m2.setName("sooo2");
		m2.setMemberId("user112");
		m2.setPassword("12345");
		m2.setPhone("010-1214-1234");
		m2.setEmail("a2a@aaa.com");
		m2.setRegdate(LocalDateTime.now());
		m2.setRole("user");
		this.memberRepository.save(m2);
		
		Member m3 = new Member();
		m3.setName("sooo3");
		m3.setMemberId("user113");
		m3.setPassword("12343");
		m3.setPhone("010-1234-1204");
		m3.setEmail("a11a@aaa.com");
		m3.setRegdate(LocalDateTime.now());
		m3.setRole("user");
		this.memberRepository.save(m3);
		
		
		
		
	}
}
