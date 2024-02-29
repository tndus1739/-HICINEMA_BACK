package com.himedia.hicinema.movie;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class Movie {
	@Id
	@Column(length=10)
	private String movieCd;

	@Column(unique = true)
	@GeneratedValue(strategy = GenerationType.AUTO)
	private int id;

	@Column(length=200)
	private String title;

	@Column(length=200)
	private String imgUrl;

	//   등급
	@Column(length=100)
	private String  rats;

	//  상영시간
	@Column(length=100)
	private String runtime;

	@Column(length=10000)
	private String content;

	//  이미지 저장 ,로 구분
	@Column(length=2000)
	private String stlls;

	//  장르
	@Column(length = 100)
	private String Genre;

	@Column(length = 200)
	private String actors;

	@Column(length = 100)
	private String director;

	@Column(length = 1000)
	private String trailerImg;

	@Column(length = 1000)
	private String trailerVideo;

	@Column(updatable = false)
	private LocalDateTime regDate;

	private LocalDateTime delDate;

	// 영화 정보를 크롤링 하면서 +7로 자동 업데이트됨 , 롯데시네마에서 내려간 영화는 업데이트가 안됨
	private LocalDateTime screenOutDate;

	@Column(length = 1)     //상태 : 기본 : O , 미노출 :  X, 삭제 : D
	private String status;


}
