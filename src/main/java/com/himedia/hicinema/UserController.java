package com.himedia.hicinema;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@Slf4j
public class UserController {

	@GetMapping(value={"", "/"})
	public String index(Model model) {
		model.addAttribute("title", "메인");
		return "user/main";
	}

	@GetMapping("/index")
	public String index2(Model model) {
		model.addAttribute("title", "관리자 메인");
		return "redirect:/";
	}

}
