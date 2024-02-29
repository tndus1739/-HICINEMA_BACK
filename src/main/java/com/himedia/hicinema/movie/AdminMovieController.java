package com.himedia.hicinema.movie;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/admin/movie")
public class AdminMovieController {

	@GetMapping("/theater_list")
	public String theaterList(Model model) {
		model.addAttribute("title", "영화관 리스트");
		return "admin/movie/theater_list";
	}

	@GetMapping("/loc_list")
	public String locList(Model model) {
		model.addAttribute("title", "지역");
		return "admin/movie/loc_list";
	}

	@GetMapping("/theater_detail")
	public String theaterDetail(Model model) {
		model.addAttribute("title", "영화관 상세");
		return "admin/movie/theater_detail";
	}

	@GetMapping("/theater_form")
	public String theaterForm(Model model) {
		model.addAttribute("title", "영화관 등록");
		return "admin/movie/theater_form";
	}

	@GetMapping("/theater_screen")
	public String theaterScreen(Model model) {
		model.addAttribute("title", "영화관 등록");
		return "admin/movie/theater_screen";
	}

	@GetMapping("/movie_list")
	public String movieList(Model model) {
		model.addAttribute("title", "상영중");
		return "admin/movie/movie_list";
	}

	@GetMapping("/movie_listSoon")
	public String movieList2(Model model) {
		model.addAttribute("title", "상영예정");
		return "admin/movie/movie_list2";
	}

	@GetMapping("/movie_listEnd")
	public String movieList3(Model model) {
		model.addAttribute("title", "상영종료");
		return "admin/movie/movie_list3";
	}

	@GetMapping("/movie_form")
	public String movieForm(Model model) {
		model.addAttribute("title", "영화 등록");
		return "admin/movie/movie_form";
	}

	@GetMapping("/movie_detail")
	public String movieDetail(Model model) {
		model.addAttribute("title", "영화 상세");
		return "admin/movie/movie_detail";
	}
	
}
