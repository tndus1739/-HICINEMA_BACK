package com.himedia.hicinema;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.himedia.hicinema.movie.Movie;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class Crawling {
	public static String crawling_movie_list() throws InterruptedException {
		WebDriverManager.edgedriver().setup();
		String baseUrl = "https://www.lottecinema.co.kr/NLCHS/Movie/List?flag=1";

		EdgeOptions options = new EdgeOptions();
		options.addArguments("--headless");
		options.addArguments("--no-sandbox");
		EdgeDriver driver = new EdgeDriver(options);
		driver.get(baseUrl);

		Thread.sleep(1000);
		List<WebElement> elements = driver.findElements(By.cssSelector(".screen_add_box"));
		JsonArray ja = new JsonArray();

		for(WebElement element : elements) {
			JsonObject jo = new JsonObject();
			String img = extractText(element, ".poster_info img", "src");
			String title = extractText(element, ".tit_info", "text").replace(extractText(element, ".ic_grade", "text"), "");
			if(!(title.equals("") || img.equals(""))) {
				jo.addProperty("title", title);
				jo.addProperty("img", img);
				ja.add(jo);
//			    ReadImage.save(img);
			}
		}
		driver.quit();
		Gson gson = new Gson();
		String json = gson.toJson(ja);
		return json;
	}

	public static String extractText(WebElement parentElement, String selector, String attribute) {
		if(attribute.equals("text")) {
			try {
				WebElement childElement = parentElement.findElement(By.cssSelector(selector));
				return childElement.getText();
			} catch (Exception e) {
				// 요소가 없을 경우 예외 처리
				return "";
			}
		} else {
			try {
				WebElement childElement = parentElement.findElement(By.cssSelector(selector));
				return childElement.getAttribute(attribute);
			} catch (Exception e) {
				// 요소가 없을 경우 예외 처리
				return "";
			}
		}
	}

	public static Movie get_movie(Movie movie) throws InterruptedException {
		WebDriverManager.edgedriver().setup();
		String movieCd = movie.getMovieCd();
		String baseUrl = "https://www.lottecinema.co.kr/NLCHS/Movie/MovieDetailView?movie=" + movieCd;

		EdgeOptions options = new EdgeOptions();
		options.addArguments("--headless");
		options.addArguments("--no-sandbox");
		EdgeDriver driver = new EdgeDriver(options);
		driver.get(baseUrl);

		Thread.sleep(1000);
		JsonObject jo = new JsonObject();

		String date = extractText(driver.findElement(By.cssSelector(".mov_info1")), "li:first-child span.roboto", "text");
		String runTime = extractText(driver.findElement(By.cssSelector(".mov_info1")), "li span.time span.roboto", "text");
		String rats = extractText(driver.findElement(By.cssSelector(".mov_info1")), "li span.grade_txt", "text");
		String content = extractText(driver.findElement(By.cssSelector(".txtarea_box.movdetailtxt")), ".txtarea", "text");
		String gen = extractText(driver.findElement(By.cssSelector(".movi_tab_info1 .detail_info2")), "li:first-child span", "text");
		String dir = extractText(driver.findElement(By.cssSelector(".movi_tab_info1 .detail_info2")), "li:nth-child(2) span.line_type", "text");
		String actors = extractText(driver.findElement(By.cssSelector(".movi_tab_info1 .detail_info2")), "li:nth-child(3) span.line_type ", "text");
		List<WebElement> stlls = driver.findElements(By.cssSelector(".stillcut_list .gridlist .gridlist_item"));

		String trailer_img = "";
		List<String> trailer_img_list = new ArrayList<>();
		String trailer_vid = "";
		List<String> trailer_vid_list = new ArrayList<>();

		if(driver.findElements(By.cssSelector(".movi_tab_info2")).size() > 0) {
			WebElement info2 = driver.findElement(By.cssSelector(".movi_tab_info2"));
			List<WebElement> cl = info2.findElements(By.cssSelector(".owl-stage .owl-item.active .item a"));
			System.out.println(cl.size());
			for(WebElement ig : cl){
				trailer_img_list.add(extractText(ig, "img", "src"));
				driver.executeScript("arguments[0].click();", ig);
//				ig.click();
				Thread.sleep(1000);
				WebElement vc = driver.findElement(By.cssSelector("#layerMovieTrailer"));
				trailer_vid_list.add(extractText(vc, "#vdoPlayer", "src"));
			}
			trailer_img = String.join(",", trailer_img_list);
			trailer_vid = String.join(",", trailer_vid_list);
		}

//		JsonArray ja_tra = new JsonArray();
//		for(WebElement tra : trailers) {
//			ja_tra.add(extractText(tra, "video", "src"));
//		}
		JsonArray ja_stl = new JsonArray();
		for (WebElement stl : stlls) {
			ja_stl.add(extractText(stl, "a img", "src"));
		}

		jo.addProperty("title", movie.getTitle());
		jo.addProperty("date", date);
		jo.addProperty("runTime", runTime);
		jo.addProperty("rats", rats);
		jo.addProperty("content", content);
		jo.addProperty("gen", gen);
		jo.addProperty("dir", dir);
		jo.addProperty("actors", actors);
//		jo.addProperty("tra", ja_tra.toString());
		jo.addProperty("stl", ja_stl.toString());
		jo.addProperty("tr_img", trailer_img);
		jo.addProperty("tr_video", trailer_vid);

		System.out.println(jo);
//		Movie movie = new Movie();
		movie.setMovieCd(movieCd);
		movie.setRats(rats);
		movie.setContent(content);
		movie.setRuntime(runTime);
		movie.setStlls(ja_stl.toString());
		movie.setActors(actors);
		movie.setDirector(dir);
		movie.setGenre(gen);
//		movie.setTitle(title);
		movie.setTrailerImg(trailer_img);
		movie.setTrailerVideo(trailer_vid);
		movie.setRegDate(LocalDateTime.now());
		movie.setScreenOutDate(LocalDateTime.now().plus(7, ChronoUnit.DAYS));

		return movie;
	}
}
