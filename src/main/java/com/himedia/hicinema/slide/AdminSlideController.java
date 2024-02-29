package com.himedia.hicinema.slide;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.himedia.hicinema.movie.AdminMovieController;

import lombok.extern.slf4j.Slf4j;

public class AdminSlideController {

	
//	@Controller
	@RequestMapping("/admin/slide")
	
//	slide/main_slide
	@GetMapping("/main_slide")
	public String mainSlide(Model model) {
		model.addAttribute("title", "메인슬라이드 등록");
		return "admin/slide/main_slide";
	} 
	
	
}
