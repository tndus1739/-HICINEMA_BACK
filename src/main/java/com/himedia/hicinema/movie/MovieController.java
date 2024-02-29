package com.himedia.hicinema.movie;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/movie")
public class MovieController {

	@GetMapping("/list")
	public String getList(Model model, @RequestParam String type) {
		System.out.println("type 변수 값 출력 : "  + type);
		model.addAttribute("title", "Movie");
		model.addAttribute("type", type);

		List<String> img_arr = new ArrayList<>();
		img_arr.add("/img_nsy/aespa_19207742.jpg");
		img_arr.add("/img_nsy/BabyShark.jpg");
		img_arr.add("/img_nsy/IfOnly_1920774.jpg");
		model.addAttribute("images", img_arr);
		return "user/movie_list";
	}

	@GetMapping("/detail/{movieCd}")
	public String getMovie(Model model, @PathVariable String movieCd) {
		model.addAttribute("title", "Movie");

		return "user/movie_detail";
	}
}
