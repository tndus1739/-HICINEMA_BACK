package com.himedia.hicinema;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestController {

//	@GetMapping("/")
//	public String index_test() {
//		return "user/main";
//	}
//
//	@GetMapping("/movie/list")
//	public String movie_list(Model model) {
//		model.addAttribute("title", "영화 리스트");
//		return "user/movie_list";
//	}
//
//	@GetMapping("/movie/detail")
//	public String movie_detail(Model model) {
//		model.addAttribute("title", "영화 상세");
//		return "user/movie_detail";
//	}
//
//	@GetMapping("/theater/detail")
//	public String theater_detail(Model model) {
//		model.addAttribute("title", "영화관 상세");
//		return "user/theater_detail";
//	}
//
//	@GetMapping("/reservation/ticketing")
//	public String ticketing(Model model) {
//		model.addAttribute("title", "예매");
//		return "user/ticketing";
//	}
//
//	@GetMapping("/reservation/seat")
//	public String seat(Model model) {
//		model.addAttribute("title", "좌석");
//		return "user/seat";
//	}
//
//	@GetMapping("/reservation/ticketing/order")
//	public String ticketing_order(Model model) {
//		model.addAttribute("title", "결제");
//		return "user/ticketing_order";
//	}
	
//	slide/main_slide
	@GetMapping("/main_slide")
	public String mainSlide(Model model) {
		model.addAttribute("title", "메인슬라이드 등록");
		return "admin/slide/main_slide";
	} 
	

}

