package com.himedia.hicinema.member;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class Member_Service_Insert {
	
	@Autowired
	private  MemberService memberService;

	@Test
	void Member_Service_Insert1() {
		
		memberService.create("홍길동", "aaa", "1234", "aaa@aaa.com", "01011112222"); 
		
		
		
	}
	
}
