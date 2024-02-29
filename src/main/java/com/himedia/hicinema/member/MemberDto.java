package com.himedia.hicinema.member;

import java.time.LocalDateTime;

import groovy.transform.builder.Builder;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;



@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MemberDto {

	
	private Long id;
	
	private String name;
	
	private String memberId;
	
	private String password;
	
	private String email;
	
	private String phone;

	private String role;

	private LocalDateTime regdate;
	
	private LocalDateTime delDate;

	private String status;
	
	
}
