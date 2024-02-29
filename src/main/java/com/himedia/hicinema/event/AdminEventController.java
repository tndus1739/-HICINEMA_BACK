package com.himedia.hicinema.event;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.himedia.hicinema.movie.AdminMovieController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/admin/event")

public class AdminEventController {
	
	@GetMapping("/event_list")
	public String eventList(Model model) {
		model.addAttribute("title", "이벤트 리스트");
		return "admin/event/event_list";
	}
	
	@GetMapping("/event_form")
	public String eventForm(Model model) {
		model.addAttribute("title", "이벤트 등록");
		return "admin/event/event_form";
	}
	
	@GetMapping("/event_detail")
	public String eventDetail(Model model) {
		model.addAttribute("title", "이벤트 수정");
		return "admin/event/event_detail";
	}

}
