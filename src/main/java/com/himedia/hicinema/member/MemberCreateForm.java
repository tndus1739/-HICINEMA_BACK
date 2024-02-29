package com.himedia.hicinema.member;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class MemberCreateForm {
	@Size(min = 4 , max = 15)     // 문자열의 길이 검증
	@NotEmpty(message = "ID를 입력해주세요.")
	private String memberId;
	
	@NotEmpty(message = "이름을 입력해주세요.")
	private String name;
	
	@Size(min = 4 , max = 15)  
	@NotEmpty(message = "비밀번호를 입력해주세요.")
	private String password1;
	
	
	@Size(min = 4 , max = 15)  
	@NotEmpty(message = "비밀번호를 확인해주세요.")
	private String password2;
	
	@NotEmpty(message = "이메일을 입력해주세요.")
	@Email    // 이메일 형식과 일치하는지 검증
	private String email;
	
	private String phone;
}
